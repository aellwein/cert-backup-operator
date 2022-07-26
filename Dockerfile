FROM scratch
WORKDIR /cert-backup-operator
ADD build/cert-backup-operator.linux /cert-backup-operator/cert-backup-operator
CMD ["./cert-backup-operator"]