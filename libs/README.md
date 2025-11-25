## Why do we have this libs folder?

Quay Keycloak images, which are used by our TestContainers-based tests, happen not be always in sync with the latest
snapshots released to Sonatype. Because we really need latest images to move on with development, we are overriding
some dependencies to point to these compatible versions from Keycloak nightly builds (on GitHub).

## Compatibility table

| Keycloak Version                         | Quay Image Tag                                                   | 
|------------------------------------------|------------------------------------------------------------------|
| 74033d310844b90e213839cb3852c0cd2776564f | cd512844bcd3b25c56decf8c2bf86298928fdf1e29139dd60f1ece8ebc82b370 |

## Final note

This folder is intended to be discarded once we have a stable build.
