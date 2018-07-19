
iaprober:
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' .

container: iaprober
	gcloud container builds submit --tag=gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober  .

container-live:
	gcloud container images add-tag gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober gcr.io/${GOOGLE_CLOUD_PROJECT}/identity-aware-prober:live

targets:
	kubectl create configmap targets --from-file=targets

auth:
	kubectl create secret generic service-account  --from-file=auth.json
