# transplaneur

## Warning: Early Development Stage

This Github repository is currently in its early development stage. As such, please note that everything is subject to change without prior notice. We are still in the process of improving and iterating on our project, so please be aware that any content or information provided may not be final. Thank you for your understanding and patience as we continue to work on this project.

If you have any questions, concerns, or suggestions, feel free to reach out to us. We welcome any feedback that can help us make this project even better. Thank you for your interest in our work, and we hope to hear from you soon.

## Docker Tags

The `transplaneur` Docker image is hosted on Docker Hub, and the tags are the same as the Git tags. However, please note that the `edge` tag is subject to change at any time without prior notice, even with breaking changes or bugs. This is because the `edge` tag is a working tag that receives the latest updates and features, and even "work in progress" application state.

We recommend that you use a specific version (vX.Y.Z) for your deployments to avoid any unexpected changes or issues.

## Deployment

### Gateway

Before using the `transplaneur` gateway, you need to configure the following environment variables with your Kubernetes cluster Pod CIDR and Service CIDR:

- CLUSTER_POD_CIDR
- CLUSTER_SVC_CIDR

Make sure to set these variables correctly to avoid any issues or errors when using the tool.