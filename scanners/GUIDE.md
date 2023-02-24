# Boostsecurity Scanner Module Guide
Guide for the Boostsecurity Scanner Module creators that want to integrate security scanners to the Boostsecurity platform. Modules are the way to integrate the scanner output to the Boostsecurity platform. The Boostsecurity CLI will use the Module configuration to execute the scanner, parse the results and send those to the platform.

## Architecture Overview

![architecture](schemas/scanner_architecture.png)

 1. The Boostsecurity CLI launches the scanner (as defined in module yaml).
 2. The Boostsecurity CLI runs the converter on the scanner output (as defined by the post-processing in module yaml). The sarif output from the converter needs to be compliant with Boostsecurity’s taxonomies.
 3. The Boostsecurity CLI creates the scanner context (org, repo, branch info, etc..), computes the fingerprint on sarif results and uploads the scan results to the Boostsecurity backend.

## Module Definition
The module.yaml file defines the module behavior and its configuration. The file is located in the root of the module directory and defines how to deal with the various phases:
    
  1. [Scanning Setup](#scanning-setup)
  2. [Scanning](#scan-with-container-image)
  3. [Post-Scanning](#scan-post-processing)

### Module Header
```yaml
api_version: 1.0 # Boostsecurity CLI Module API Version

id: <id> # Unique ID of the module
name: <name> # Display Name of the module
namespace: <namespace> # Namespace of the module rules
```
Namespace is used to group module rules. Rules can be shared across multiple modules if they are in the same namespace.

### Differential and Full Scanning
The Boostsecurity CLI can run modules in two different modes: differential and main scanning. The differential scanning mode is used to scan only the files that have changed between two commits. This is usually used in the context of Pull Requests to only scan the changes introduced. The full(or main) scanning mode is used to scan the whole codebase.

```yaml
config:
  support_diff_scan: true # true if the module supports differential scanning
```

### Scanning Formats
The Boostsecurity CLI can ingest the scanner output in different formats: Sarif and CycloneDX. The module.yaml file defines the supported format of a Module.

The CycloneDX format is used for SBOM modules and Sarif is for asset security scanning.

```yaml
steps:
- scan:
    command:
      ...
    format: sarif # sarif or cyclonedx
```


#### Sarif
The Sarif output format is a JSON based format that is used by many security scanners. Sarif is the expected format for security scan results. The Boostsecurity CLI will parse the Sarif output and send the results to the Boostsecurity platform.

The Boostsecurity platform provides extensions to the Sarif format, known as [Taxonomies](schemas/sarif-schema.json), which are used to provide additional metadata about findings issued by various scanners.

The following types of findings are supported by the platform:

 * Static application security testing(SAST) Scan Result
    
   [SAST Scan Result JSON Schema](schemas/sast-schema.json)
 * Software Composition Analysis(SCA) Result
    
   [SCA Scan Result JSON Schema](schemas/sca-schema.json)
 * Container Scan Result
    
   Similar to an SCA type but with extra metadata about the container image.
  
   [Container Scan Result JSON Schema](schemas/container-schema.json)



#### CycloneDX
The CycloneDX is a Software Bill of Materials(SBOM) format used to inventory the software components used in a project. The Boostsecurity CLI will parse the CycloneDX output and send the results to the platform. Results will be visible in the SBOM section.

### Scanning

#### Scanning Setup
The optional setup section may be used to download or prepare utilities that would be used by this module. These steps will be executed only once before the scans occur.

In subsequent steps, any files made available in this temporary directory may be referenced via the `$SETUP_PATH` variable.

```yaml
setup:
  - name: Install post-processing dependency
    run: |
      curl -fsSL -O "https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64"
      echo "af986793a515d500ab2d35f8d2aecd656e764504b789b66d7e1a0b727a124c44  jq-linux64" | sha256sum --check
      chmod +x jq-linux64
```

#### Scan with Container Image
The container image is pulled and run inside the CI environment to execute the scan.
```yaml
steps:
- scan:
    command:
      docker:
        image: <image>
        command: <container command> # optional
        entrypoint: <container entrypoint> # optional
        workdir: <container workdir> # optional the git repo will be mounted to this directory
        environment:
          ENVVARIABLE: <value>
    format: ...
```


#### Scan with Executable
The executable is run inside the CI environment to execute the scan. Requires that the executable has been installed in the setup step.
```yaml
steps:
- scan:
    command:
      environment:
        ENVVARIABLE: <value>
      run: |
        $SETUP_PATH/<executable>
    format: ...
```

#### Scan Post-Processing
The post-processing step is used to process the scanner output before sending it to the Boostsecurity platform. It is executed after the scan step and is optional.

##### Post-Processing using a Container Image
```yaml
steps:
- scan:
    command:
      ...
    format: ...
    post-processor:
      docker:
        image: <image>
        command: <container command>
        environment:
          ENVVARIABLE: <value>
```
##### Post-Processing using an Executable
Requires the executable to have been installed in the setup step.
```yaml
steps:
- scan:
    command:
      ...
    format: ...
    post-processor:
      run: $SETUP_PATH/<executable>
```

## Module Rules
Module rules are used to enrich the findings to ensure the policy processing per proper group or categories as well as the proper display of the description in the Boostsecurity platform. 

The rules are defined in the rules.yaml file. The file is located in the root of the module directory.

```yaml
rules:
  G111: # Unique ID of the rule
    categories: # Categories/Labels of the rule. The available options are defined in the Boostsecurity platform.
    - ALL
    - cwe-22
    - boost-baseline
    - boost-hardened
    - cwe-top-25
    - owasp-top-10
    group: top10-broken-access-control # Group of the rule. Used for display and aggregation in the Boostsecurity platform. The available groups are defined in the platform.
    name: G111 # Unique ID of the rule
    pretty_name: 'G111: Potential directory traversal' # Display name of the rule
    description: <description>
    ref: <ref> # Reference URL of the rule
```
## Taxonomies
Taxonomies are required for proper parsing and processing of results in the Boostsecurity platform. Sarif output without taxonomies will not be parsed by the platform.
### SAST
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
     {
        "tool": {
           "driver": {
              "name": "checkov",
              "organization": "bridgecrew",
              "version": "2.0.563",
              "rules": [
                 {
                    "id": "BOOST_AWS_130",
                    "relationships": [
                       {
                          "target": {
                             "id": "BOOST_AWS_130",
                             "index": -1,
                             "toolComponent": {
                                "name": "boost/sast",
                                "index": -1
                             }
                          },
                          "kinds": [
                             "relevant"
                          ]
                       }
                    ]
                 }
              ],
              "supportedTaxonomies": [
                 {
                    "name": "boost/sast",
                    "index": -1
                 }
              ]
           },
           "extensions": []
        },
        "results": [
           {
              "ruleId": "BOOST_AWS_130",
              "level": "warning",
              "message": {
                 "text": "Ensure VPC subnets do not assign public IP by default",
                 "arguments": []
              },
              "taxa": [
                 {
                    "id": "BOOST_AWS_130",
                    "index": -1,
                    "toolComponent": {
                       "name": "boost/sast",
                       "index": -1
                    }
                 }
              ]
           }
        ],
        "taxonomies": [
           {
              "name": "boost/sast",
              "organization": "boostsecurity",
              "version": "1.0.0",
              "notifications": [],
              "rules": [],
              "taxa": [
                 {
                    "id": "BOOST_AWS_130",
                    "name": "aws-vpc-assign-public-ip",
                    "relationships": []
                 }
              ]
           }
        ]
     }
  ]
}

```

### SCA
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "npm audit",
          "rules": [
            {
              "id": "1089153",
              "shortDescription": {
                "text": "jsonwebtoken (<=8.5.1)"
              },
              "fullDescription": {
                "text": "jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC (<=8.5.1)"
              },
              "relationships": [
                {
                  "target": {
                    "id": "cve-moderate",
                    "index": -1,
                    "toolComponent": {
                      "name": "boost/sca",
                      "index": -1
                    }
                  },
                  "kinds": [
                    "relevant"
                  ]
                }
              ]
            },
            {
              "id": "1090161",
              "shortDescription": {
                "text": "luxon (>=2.0.0 <2.5.2)"
              },
              "fullDescription": {
                "text": "Luxon Inefficient Regular Expression Complexity vulnerability (>=2.0.0 <2.5.2)"
              },
              "relationships": [
                {
                  "target": {
                    "id": "cve-high",
                    "index": -1,
                    "toolComponent": {
                      "name": "boost/sca",
                      "index": -1
                    }
                  },
                  "kinds": [
                    "relevant"
                  ]
                }
              ]
            }
          ],
          "supportedTaxonomies": [
            {
              "name": "boost/sca",
              "index": -1
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "1089153",
          "level": "warning",
          "message": {
            "text": "This file introduces a vulnerable jsonwebtoken npm package with a moderate severity vulnerability."
          },
          "taxa": [
            {
              "id": "cve-moderate",
              "index": -1,
              "toolComponent": {
                "name": "boost/sca",
                "index": -1
              },
              "properties": {
                "tags": [],
                "advisory_link": "https://github.com/advisories/GHSA-hjrf-2m68-5959",
                "cve": "GHSA-hjrf-2m68-5959",
                "cvss_score": 5.0,
                "impacted_versions": "<=8.5.1",
                "package_name": "jsonwebtoken",
                "package_ecosystem": "npm"
              }
            }
          ]
        },
        {
          "ruleId": "1090161",
          "message": {
            "text": "This file introduces a vulnerable luxon npm package with a high severity vulnerability.",
            "arguments": []
          },
          "taxa": [
            {
              "id": "cve-high",
              "index": -1,
              "toolComponent": {
                "name": "boost/sca",
                "index": -1
              },
              "properties": {
                "tags": [],
                "advisory_link": "https://github.com/advisories/GHSA-3xq5-wjfh-ppjc",
                "cve": "GHSA-3xq5-wjfh-ppjc",
                "cvss_score": 7.5,
                "impacted_versions": ">=2.0.0 <2.5.2",
                "package_name": "luxon",
                "package_ecosystem": "npm"
              }
            }
          ]
        }
      ],
      "taxonomies": [
        {
          "name": "boost/sca",
          "organization": "boostsecurity",
          "version": "1.0.0",
          "notifications": [],
          "rules": [],
          "taxa": [
            {
              "id": "cve-unknown",
              "defaultConfiguration": {
                "enabled": true,
                "level": "none",
                "rank": -1.0
              },
              "relationships": []
            },
            {
              "id": "cve-low",
              "defaultConfiguration": {
                "enabled": true,
                "level": "note",
                "rank": -1.0
              },
              "relationships": []
            },
            {
              "id": "cve-moderate",
              "defaultConfiguration": {
                "enabled": true,
                "level": "warning",
                "rank": -1.0
              },
              "relationships": []
            },
            {
              "id": "cve-high",
              "defaultConfiguration": {
                "enabled": true,
                "level": "error",
                "rank": -1.0
              },
              "relationships": []
            },
            {
              "id": "cve-critical",
              "defaultConfiguration": {
                "enabled": true,
                "level": "error",
                "rank": -1.0
              },
              "relationships": []
            }
          ],
          "supportedTaxonomies": []
        }
      ]
    }
  ]
}
```
### Container
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "trivy",
          "rules": [
            {
              "id": "CVE-2022-37434",
              "name": "CVE-2022-37434",
              "shortDescription": {
                "text": "zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field"
              },
              "fullDescription": {
                "text": "zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference)."
              },
              "relationships": [
                {
                  "target": {
                    "id": "cve-critical",
                    "toolComponent": {
                      "name": "boost/cont_scanning"
                    }
                  }
                }
              ]
            }
          ],
          "supportedTaxonomies": [
            {
              "name": "boost/cont_scanning"
            }
          ]
        }
      },
      "invocations": [
        {
          "executionSuccessful": true
        }
      ],
      "results": [
        {
          "ruleId": "CVE-2022-37434",
          "level": "error",
          "message": {
            "text": "zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field"
          },
          "taxa": [
            {
              "id": "cve-critical",
              "toolComponent": {
                "name": "boost/cont_scanning"
              },
              "properties": {
                "tags": [
                  "your-image:tag"
                ],
                "advisory_link": "https://avd.aquasec.com/nvd/cve-2022-37434",
                "cve": "CVE-2022-37434",
                "cvss_score": 9.8,
                "ecosystem": "alpine",
                "image_name": "your-image",
                "image_version": "sha256:bcf064d8bd917f52798522dbe7f201e335282f0066c6c777e44552bd79f8e946",
                "layer_id": "sha256:5b7df235d876e8cd4a2a329ae786db3fb152eff939f88379c49bcaaabbafbd9c",
                "package_name": "zlib"
              }
            }
          ]
        }
      ],
      "taxonomies": [
        {
          "name": "boost/cont_scanning",
          "taxa": [
            {
              "id": "cve-critical"
            },
            {
              "id": "cve-high"
            },
            {
              "id": "cve-low"
            },
            {
              "id": "cve-moderate"
            },
            {
              "id": "cve-unknown"
            }
          ]
        }
      ]
    }
  ]
}


```
## Examples

### Security Scanner using Container
```yaml
api_version: 1.0

id: boostsecurityio/brakeman
name: BoostSecurity Brakeman
namespace: boostsecurityio/brakeman

config:
  support_diff_scan: true
  require_full_repo: true

steps:
  - scan:
      command:
        docker:
          image: presidentbeef/brakeman:latest@sha256:7416e4cf46131d5f920be496485d30d55a9b9f00acec28847ae1e5f10ac837f4
          command: --format json --quiet --no-pager --no-exit-on-warn --no-exit-on-error --force /src
          workdir: /src
      format: sarif
      post-processor:
        docker:
          image: public.ecr.aws/boostsecurityio/boost-scanner-brakeman:0b71fa2@sha256:1cf820c9b7eb7c5869814ca125b220d788f6a0cf02f83266bb722a9a2674240a

```
### Security Scanner using an executable(With multi arch support)
```yaml
api_version: 1.0


id: boostsecurityio/osv-scanner
name: BoostSecurity osv-scanner
namespace: boostsecurityio/osv-scanner


config:
   support_diff_scan: true
   include_files:
   - buildscript-gradle.lockfile
   - Cargo.lock
   - composer.lock
   - conan.lock
   - Gemfile.lock
   - go.mod
   - gradle.lockfile
   - mix.lock
   - package-lock.json
   - packages.lock.json
   - Pipfile.lock
   - pnpm-lock.yaml
   - poetry.lock
   - pom.xml
   - pubspec.lock
   - requirements.txt
   - yarn.lock

setup:
- name: Install OSV-Scanner
  environment:
     VERSION: 1.1.0
     LINUX_X86_64_SHA: 73b3b297f0a9a3fa28ea45fd45b3b9e74e5a0044ec1c03693a4e8aff0d169f86
     LINUX_ARM64_SHA: fed5a1109f45410d8bcecba852aab48f1812b5254e3cfdd2950ef9330e9e29c2
     MACOS_ARM64_SHA: 65fa9c435535fd58cc1fd6878a09009c44d608c749c41b8f7a7e4727cda0e6ee
  run: |
     BINARY_URL="https://github.com/google/osv-scanner/releases/download/v${VERSION}"
     ARCH=$(uname -m)
     case "$(uname -sm)" in
       "Linux x86_64")
         BINARY_URL="${BINARY_URL}/osv-scanner_${VERSION}_linux_amd64"
         SHA="${LINUX_X86_64_SHA} osv-scanner"
         ;;
       "Linux aarch64")
         BINARY_URL="${BINARY_URL}/osv-scanner_${VERSION}_linux_arm64"
         SHA="${LINUX_ARM64_SHA} osv-scanner"
         ;;
       "Darwin arm64")
         BINARY_URL="${BINARY_URL}/osv-scanner_${VERSION}_darwin_arm64"
         SHA="${MACOS_ARM64_SHA} osv-scanner"
         ;;
       *)
         echo "Unsupported machine: ${OPTARG}"
         exit 1
         ;;
     esac
     curl -o osv-scanner -fsSL "${BINARY_URL}"
     echo "${SHA}" | sha256sum --check

     chmod +x osv-scanner

steps:
- scan:
     command:
        run: |
           if ! $SETUP_PATH/osv-scanner --recursive --json .; then
             if test $? -gt 2; then
               echo "osv-scanner failed to execute"
               exit 1
             fi
           fi
        environment:
           HOME: /tmp
     format: sarif
     post-processor:
        docker:
           image: public.ecr.aws/boostsecurityio/boost-converter-sca:0b7418a@sha256:231b8276beb9fb14258a77cf53d799bac1e77f35b89fd587ad1228d79df88984
           command: process --scanner osv
           environment:
              PYTHONIOENCODING: utf-8
```
### SBOM Module Example
```yaml
api_version: 1.0

id: boostsecurityio/trivy-sbom
name: BoostSecurity Trivy (FS SBOM)
namespace: boostsecurityio/trivy-sbom


config:
  support_diff_scan: false


steps:
 - scan:
     command:
       docker:
        image: aquasec/trivy:0.37.3@sha256:906c909a441949317c252039ce8543ef79bcb9a59e7dd9b94e619191b82fedd2
        command: fs --format=cyclonedx --cache-dir=/tmp/trivy/ /app
        workdir: /app
     format: cyclonedx
```
