pipeline {
   agent any
   options { checkoutToSubdirectory('trustme/cml') }

   stages {
      stage('Repo') {
	 steps {
             sh 'repo init -u https://github.com/trustm3/trustme_main.git -b zeus -m yocto-x86-genericx86-64.xml'
             sh 'mkdir -p .repo/local_manifests'
             sh '''
                echo "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>" > .repo/local_manifests/jenkins.xml
                echo "<manifest>" >> .repo/local_manifests/jenkins.xml
                echo "<remote name=\\\"git-int\\\" fetch=\\\"https://git-int.aisec.fraunhofer.de\\\" />" >> .repo/local_manifests/jenkins.xml
                echo "<remove-project name=\\\"device_fraunhofer_common_cml\\\" />" >> .repo/local_manifests/jenkins.xml
                echo "</manifest>" >> .repo/local_manifests/jenkins.xml
             '''
             sh 'repo sync -j8'
             sh '''
               echo branch name from Jenkins: ${BRANCH_NAME}
               cd ${WORKSPACE}/trustme/cml
               if [ ! -z $(git branch --list ${BRANCH_NAME}) ]; then
                  git branch -D ${BRANCH_NAME}
               fi
               git checkout -b ${BRANCH_NAME}
               git clean -f
             '''
         }
      }

      stage('Inspect the Codebase') {
          parallel {
              stage('Code Format & Style') {
                  agent {
                      dockerfile {
                          /*TODO: update the Dockerfile in the build repo instead*/
                          dir 'trustme/cml/scripts/ci'
                          args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
                          reuseNode true
                      }
                  }
                  steps {
                      sh 'trustme/cml/scripts/ci/check-if-code-is-formatted.sh'
                  }
              }

              /*
                Intentionally mark the static code analysis stage as skipped
                We want to show that we are performing static code analysis, but not
                as part of Jenkins's pipeline.
               */
              stage('Static Code Analysis') {
                  when {
                      expression {
                          return false
                      }
                  }
                  steps {
                      sh '''
                        echo "Static Code Analysis is performed using Semmle."
                        echo "Please check GitHub's project for results from Semmle's analysis."
                      '''
                  }
              }
          }
      }

      stage('Unit Testing') {
          agent {
              dockerfile {
                  dir 'trustme/cml/scripts/ci'
                  args '--entrypoint=\'\''
                  reuseNode true
              }
          }
          steps {
              sh 'trustme/cml/scripts/ci/unit-testing.sh'
          }
       }

        /*TODO: saving images not tested*/
      stage('Yocto Build') {
          parallel {
              stage('Development Image') {
                  agent {
                      dockerfile {
                          dir 'trustme/cml/scripts/ci'
                          args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
                          reuseNode true
                      }
                  }

                   steps {
                      sh '''
                         export LC_ALL=en_US.UTF-8
                         export LANG=en_US.UTF-8
                         export LANGUAGE=en_US.UTF-8
                         SANITIZERS=y
                         if [ -d out-yocto/conf ]; then
                            rm -r out-yocto/conf
                         fi
                         . init_ws.sh out-yocto

                         echo Using branch name ${BRANCH_NAME} in bbappend files
                         cd ${WORKSPACE}/out-yocto
                         echo "BRANCH = \\\"${BRANCH_NAME}\\\"" > cmld_git.bbappend.jenkins
                         cat cmld_git.bbappend >> cmld_git.bbappend.jenkins
                         rm cmld_git.bbappend
                         cp cmld_git.bbappend.jenkins cmld_git.bbappend

                         echo "SOURCE_MIRROR_URL ?= \\\"file:///source_mirror/sources/\\\"" >> conf/local.conf
                         echo "INHERIT += \\\"own-mirrors\\\"" >> conf/local.conf
                         echo "BB_GENERATE_MIRROR_TARBALLS = \\\"1\\\"" >> conf/local.conf

                         bitbake trustx-cml-initramfs multiconfig:container:trustx-core
                         bitbake trustx-cml
                      '''
                   }

                   post {
                      success {
                         sh '''
                            xz -T 0 -f out-yocto/tmp/deploy/images/**/trustme_image/trustmeimage.img
                         '''

                         archiveArtifacts artifacts: 'out-yocto/tmp/deploy/images/**/trustme_image/trustmeimage.img.xz', fingerprint: true
                      }
                   }
 
              }

              stage('Production Image') {
                  agent {
                      dockerfile {
                          dir 'trustme/cml/scripts/ci'
                          args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
                          reuseNode true
                      }
                  }

                   steps {
                      sh '''
                         export LC_ALL=en_US.UTF-8
                         export LANG=en_US.UTF-8
                         export LANGUAGE=en_US.UTF-8
                         DEVELOPMENT_BUILD=n
                         if [ -d out-prod/conf ]; then
                            rm -r out-prod/conf
                         fi
                         . init_ws.sh out-prod

                         echo Using branch name ${BRANCH_NAME} in bbappend files
                         cd ${WORKSPACE}/out-prod
                         echo "BRANCH = \\\"${BRANCH_NAME}\\\"" > cmld_git.bbappend.jenkins
                         cat cmld_git.bbappend >> cmld_git.bbappend.jenkins
                         rm cmld_git.bbappend
                         cp cmld_git.bbappend.jenkins cmld_git.bbappend

                         echo "SOURCE_MIRROR_URL ?= \\\"file:///source_mirror/sources/\\\"" >> conf/local.conf
                         echo "INHERIT += \\\"own-mirrors\\\"" >> conf/local.conf
                         echo "BB_GENERATE_MIRROR_TARBALLS = \\\"1\\\"" >> conf/local.conf

                         bitbake trustx-cml-initramfs multiconfig:container:trustx-core
                         bitbake trustx-cml
                      '''
                   }
                   post {
                      success {
                         sh '''
                            xz -T 0 -f out-prod/tmp/deploy/images/**/trustme_image/trustmeimage.img
                         '''

                         archiveArtifacts artifacts: 'out-prod/tmp/deploy/images/**/trustme_image/trustmeimage.img.xz', fingerprint: true
                      }
                   }
              }
          }
      }


       /*TODO: integrate with yocto's QEMU testing framework to run tests inside a running instance*/
      stage('Integration Testing') {
          parallel {
              stage('Development Image') {
                  /*TODO;Skipped for now*/
                  when {
                      expression {
                          return false
                      }
                  }
                  steps {
                      sh 'echo pass'
                  }
              }

              stage('Production Image') {
                  /*TODO;Skipped for now*/
                  when {
                      expression {
                          return false
                      }
                  }
                  steps {
                      sh 'echo pass'
                  }
              }
          }
      }

      /*TODO deploy the development and production images on separate machines
        and start demo applications inside them (e.g. a webserver)*/
      stage('Live Deployment') {
          parallel {
              stage('Development Image') {
                  /*TODO;Skipped for now*/
                  when {
                      expression {
                          /*If branch trustx master and comes from main repo?*/
                          return false
                      }
                  }
                  steps {
                      sh 'echo pass'
                  }
              }

              stage('Production Image') {
                  /*TODO;Skipped for now*/
                  when {
                      expression {
                          /*If branch trustx master and comes from main repo?*/
                          return false
                      }
                  }
                  steps {
                      sh 'echo pass'
                  }
              }
          }
      }

      stage('Documentation Generation') {
          /*TODO;Skipped for now*/
          when {
              expression {
                  /*If branch trustx master and comes from main repo?*/
                  return false
              }
          }
          steps {
              sh 'echo pass'
          }
      }
   }
}
