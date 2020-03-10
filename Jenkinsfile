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
                echo "<project path=\\\"codesonar-docker\\\" name=\\\"braunsdo/codesonar-docker\\\" remote=\\\"git-int\\\" revision=\\\"trustme\\\" />" >> .repo/local_manifests/jenkins.xml
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
             '''
         }
      }
      stage('Build') {
         parallel {
            stage('Bitbake') {
               agent { dockerfile {
                  dir 'trustme/build/yocto/docker'
                  args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
                  reuseNode true
               } }
               steps {
                  sh '''
                     export LC_ALL=en_US.UTF-8
                     export LANG=en_US.UTF-8
                     export LANGUAGE=en_US.UTF-8
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
                  '''
               }
            }
            stage('Static_Analysis') {
               agent { dockerfile {
                  dir 'codesonar-docker'
                  args '--entrypoint=\'\' -v /etc/passwd:/etc/passwd:ro'
                  reuseNode true
               } }
               steps {
                  script {
                     try {
                        sh '''
                           export HOME=${WORKSPACE}
                           cd ${WORKSPACE}/trustme/cml
                           sh ${WORKSPACE}/codesonar-docker/docker-entrypoint.sh
                        '''
                     } catch (Exception e) {
			currentBuild.result = 'SUCCESS'
                     }
                  }
               }
            }
         }
      }
      stage('Deploy') {
         agent { dockerfile {
            dir 'trustme/build/yocto/docker'
            args '--entrypoint=\'\' -v /tmp:/tmp'
            reuseNode true
         } }
         steps {
            sh '''
               export LC_ALL=en_US.UTF-8
               export LANG=en_US.UTF-8
               export LANGUAGE=en_US.UTF-8
               . init_ws.sh out-yocto
               rm cmld_git.bbappend
               cp cmld_git.bbappend.jenkins cmld_git.bbappend

               bitbake trustx-cml
            '''
         }
      }
      stage('Update_Mirror') {
         agent { dockerfile {
            dir 'trustme/build/yocto/docker'
            args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
            reuseNode true
         } }
         steps {
            sh '''
               export LC_ALL=en_US.UTF-8
               export LANG=en_US.UTF-8
               export LANGUAGE=en_US.UTF-8

               umask 002

               if [ ! -d /source_mirror/sources ]; then
                  mkdir /source_mirror/sources
               fi
               for i in out-yocto/downloads/*; do
                  if [ -f $i ] && [ ! -L $i ]; then
                     cp -v $i /source_mirror/sources/
                  fi
               done
            '''
         }
      }
   }

   post {
      always {
         sh '''
            xz -T 0 -f out-yocto/tmp/deploy/images/**/trustme_image/trustmeimage.img
         '''

         archiveArtifacts artifacts: 'out-yocto/tmp/deploy/images/**/trustme_image/trustmeimage.img.xz', fingerprint: true
      }
   }
}
