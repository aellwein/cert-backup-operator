package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	cert_v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func expandPrefix(s string) string {
	if strings.HasPrefix(s, "~") {
		usr, err := user.Current()
		if err != nil {
			panic("unable to get current user")
		}
		return strings.Replace(s, "~", usr.HomeDir, 1)
	}
	return s
}

func main() {
	var (
		kubeconfig   *string
		certLocation *string
	)

	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	certLocation = flag.String("certlocation", expandPrefix("~/cert-backup"), "absolute path to folder where certificate backups are created")
	flag.Parse()

	config, err := rest.InClusterConfig()
	log.Println("trying in-cluster configuration...")
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			log.Panicf("unable to get client config: %v\n", err)
		}
		log.Println("We are outside of k8s cluster, using kubeconfig...")
		// we are not in cluster, try to get config from env
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.Panicf("unable to build client config: %v\n", err)
		}
	}
	clientset, err := versioned.NewForConfig(config)
	if err != nil {
		log.Panicf("unable to create clientset: %v\n", err)
	}

	// Initially we listing certificates, later we will watch them
	log.Println("Listing certificates...")
	certList, err := clientset.CertmanagerV1().Certificates("").List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Printf("unable to list certificates, error: %v\n", err)
		// ignore the error for now...
	} else {
		for _, i := range certList.Items {
			backupCertIfReady(&i, config, *certLocation)
		}
	}
	quitChan := make(chan os.Signal, 1)
	signal.Notify(quitChan, os.Interrupt, syscall.SIGTERM)
	log.Println("Start watching certificates...")
	w, err := clientset.CertmanagerV1().Certificates("").Watch(context.TODO(), v1.ListOptions{})

	// watch certs
	go func(wi watch.Interface) {
		if err != nil {
			log.Panicf("Error watching for certificates: %v\n", err)
		}
		for event := range w.ResultChan() {
			cert := event.Object.(*cert_v1.Certificate)
			switch event.Type {
			case watch.Added, watch.Modified:
				backupCertIfReady(cert, config, *certLocation)
			}
		}
	}(w)

	sig := <-quitChan
	if w != nil {
		w.Stop()
	}
	log.Printf("Exiting program due to '%v' signal.\n", sig)
}

// backup certificate at given location (if not yet already)
func backup(cert cert_v1.Certificate, certLocation string, certBytes []byte, certKeyBytes []byte) error {
	certFname := fmt.Sprintf("%s_%s_%04d%02d%02d_%02d%02d%02d.crt",
		cert.Namespace,
		cert.Name,
		cert.CreationTimestamp.Year(),
		cert.CreationTimestamp.Month(),
		cert.CreationTimestamp.Day(),
		cert.CreationTimestamp.Hour(),
		cert.CreationTimestamp.Minute(),
		cert.CreationTimestamp.Second(),
	)
	certKeyFname := fmt.Sprintf("%s_%s_%04d%02d%02d_%02d%02d%02d.key",
		cert.Namespace,
		cert.Name,
		cert.CreationTimestamp.Year(),
		cert.CreationTimestamp.Month(),
		cert.CreationTimestamp.Day(),
		cert.CreationTimestamp.Hour(),
		cert.CreationTimestamp.Minute(),
		cert.CreationTimestamp.Second(),
	)

	fpathCert := filepath.Join(certLocation, certFname)
	fpathKey := filepath.Join(certLocation, certKeyFname)
	if _, err := os.Stat(fpathCert); errors.Is(err, os.ErrNotExist) {
		log.Printf("Saving certificate %s/%s to %s...\n", cert.Namespace, cert.Name, fpathCert)
		err := os.WriteFile(fpathCert, certBytes, 0o700)
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(fpathKey); errors.Is(err, os.ErrNotExist) {
		log.Printf("Saving cert key for %s/%s to %s...\n", cert.Namespace, cert.Name, fpathKey)
		err := os.WriteFile(fpathKey, certKeyBytes, 0o700)
		if err != nil {
			return err
		}
	}
	return nil
}

func backupCertIfReady(c *cert_v1.Certificate, config *rest.Config, certLocation string) {
	if len(c.Status.Conditions) > 0 {
		if c.Status.Conditions[0].Type == cert_v1.CertificateConditionReady {
			// certificate is ready, we can backup it
			cert, certKey, err := getCertContent(config, c.Namespace, c.Name)
			if err != nil {
				log.Panicf("Unable to get certificate content for %s in namespace %s: %v\n", c.Name, c.Namespace, err)
			}
			if err := backup(*c, certLocation, cert, certKey); err != nil {
				log.Printf("Error while backup certificate '%s' from namespace %s: %v\n", c.Name, c.Namespace, err)
				// ignore the error for now...
			}
		}
	} else {
		log.Printf("Certificate '%s' from namespace %s doesn't have conditions. Ignoring...", c.Name, c.Namespace)
	}
}

func getCertContent(config *rest.Config, namespace string, name string) ([]byte, []byte, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}
	secr, err := clientset.CoreV1().Secrets(namespace).Get(context.TODO(), name, v1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	return secr.Data["tls.crt"], secr.Data["tls.key"], nil
}
