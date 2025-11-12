# Build the Docker image and create the RPM
docker build -f Dockerfile.rhel7 -t cnetflow-rhel7-builder .

# Extract the RPM from the container
docker create --name temp cnetflow-rhel7-builder
docker cp temp:/build/build/cnetflow-1.0.0-1.el7.x86_64.rpm .
docker rm temp