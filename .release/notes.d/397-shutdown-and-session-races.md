## Reliability

- **Clean exits.** The server can no longer crash while exiting after a stop or restart when web or device sessions were still connected (seen as a segmentation fault on Linux and an abort on macOS).
- **Share-link uploads.** A share-link upload could rarely be refused with "Malformed share token prefix" while another request on the same link was being handled. Fixed.
- **Upstream event sync.** Stopping the server in the middle of applying bucket events no longer counts the interrupted object as a failed attempt; it is applied on the next start.
