pipeline {
   agent any
   options { checkoutToSubdirectory('trustme/cml') }
   stages {
      stage('Repo') {
	 steps {
             sh 'repo init -u https://github.com/trustm3/trustme_main.git -b master -m ids-x86-yocto.xml'
             sh 'mkdir -p .repo/local_manifests'
             sh '''
                echo "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>" > .repo/local_manifests/jenkins.xml
                echo "<manifest><remove-project name=\\\"device_fraunhofer_common_cml\\\" /></manifest>" >> .repo/local_manifests/jenkins.xml
             '''
             sh 'repo sync -j8'
         }
      }
      stage('Build') {
         agent { dockerfile {
            dir 'trustme/build/yocto/docker'
            args '--entrypoint=\'\''
            reuseNode true
         } }
         steps {
            sh '''
               export LC_ALL=en_US.UTF-8
               export LANG=en_US.UTF-8
               export LANGUAGE=en_US.UTF-8
               echo branch name from Jenkins: ${BRANCH_NAME}
               . init_ws.sh out-yocto

               cd ${WORKSPACE}/trustme/cml
               if [ ! -z $(git branch --list ${BRANCH_NAME}) ]; then
                  git branch -D ${BRANCH_NAME}
               fi
               git checkout -b ${BRANCH_NAME}
               cd ${WORKSPACE}/out-yocto
               echo "BRANCH = \\\"${BRANCH_NAME}\\\"" > cmld_git.bbappend.jenkins
               cat cmld_git.bbappend >> cmld_git.bbappend.jenkins
               rm cmld_git.bbappend
               cp cmld_git.bbappend.jenkins cmld_git.bbappend

               bitbake trustx-cml-initramfs multiconfig:container:trustx-core
            '''
         }
      }
      stage('Deploy') {
         agent { dockerfile {
            dir 'trustme/build/yocto/docker'
            args '--entrypoint=\'\''
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
   }

   post {
      archiveArtifacts artifacts: 'out-yocto/tmp/deploy/images/**/trustme_image/trustmeimage.img', fingerprint: true
   }
}
