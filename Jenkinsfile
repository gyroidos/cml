pipeline {
   agent any

   options { checkoutToSubdirectory('trustme/cml') }

   stages {
      stage('Repo') {
         exws (tme-ws) {
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
     }
	    }
    }
}
