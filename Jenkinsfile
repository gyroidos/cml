pipeline {
	agent any
	options { checkoutToSubdirectory('trustme/cml') }

	stages {


		stage('Repo') {
			steps {
				sh label: 'Clean workspace and repo init', script: '''
					echo "Running on $(hostname)"
					rm -fr ${WORKSPACE}/.repo ${WORKSPACE}/meta-* ${WORKSPACE}/out-* ${WORKSPACE}/trustme/build ${WORKSPACE}/poky trustme/manifest

					manifest_branch=${CHANGE_TARGET}
					if [ -z "${manifest_branch}" ]; then
						manifest_branch=${BRANCH_NAME}
					fi
					repo init -u https://github.com/gyroidos/gyroidos.git -b ${manifest_branch} -m yocto-x86-genericx86-64.xml
				'''

				sh label: 'Adapt manifest for jenkins', script: '''
					mkdir -p .repo/local_manifests

					echo "<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>" > .repo/local_manifests/jenkins.xml
					echo "<manifest>" >> .repo/local_manifests/jenkins.xml
					echo "<remote name=\\\"git-int\\\" fetch=\\\"https://git-int.aisec.fraunhofer.de\\\" />" >> .repo/local_manifests/jenkins.xml
					echo "<remove-project name=\\\"cml\\\" />" >> .repo/local_manifests/jenkins.xml
					echo "</manifest>" >> .repo/local_manifests/jenkins.xml
				'''
				sh 'repo sync -j8'
				sh label: 'Prepare trustme/cml', script: '''
					echo branch name from Jenkins: ${BRANCH_NAME}
					cd ${WORKSPACE}/trustme/cml
					if [ ! -z $(git branch --list ${BRANCH_NAME}) ]; then
						git branch -D ${BRANCH_NAME}
					fi
					git checkout -b ${BRANCH_NAME}
					git clean -f
				'''

				stash excludes: '.repo/.**', includes: '**', name: 'ws-yocto', useDefaultExcludes: false, allowEmpty: false
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
						}
					}
					steps {
						sh label: 'Check code formatting', script: 'trustme/cml/scripts/ci/check-if-code-is-formatted.sh'
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
						sh label: 'Perform static code analysis', script: '''
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
				sh label: 'Perform unit tests', script: 'trustme/cml/scripts/ci/unit-testing.sh'
			}
		}
		stage('Build + Test Images') {
			// Build images in parallel
			matrix {
				axes {
					axis {
						name 'BUILDTYPE'
						values 'dev', 'production', 'ccmode', 'schsm'
					}
				}
				stages {
					stage('Build Image') {
						agent {
							dockerfile {
								dir "trustme/cml/scripts/ci"
								args '--entrypoint=\'\' -v /yocto_mirror/sources:/source_mirror -v /yocto_mirror/sstate-cache:/sstate_mirror --env BUILDNODE="${env.NODE_NAME}"'
								reuseNode false
							}
						}
						steps {
							sh label: 'Clean up workspace', script: '''
								find "${WORKSPACE}" -exec rm -fr {} \\;
							'''

							unstash 'ws-yocto'
							sh label: 'Perform Yocto build', script: '''
								echo "Running on host: ${NODE_NAME}"
								export LC_ALL=en_US.UTF-8
								export LANG=en_US.UTF-8
								export LANGUAGE=en_US.UTF-8

								if [ "dev" = ${BUILDTYPE} ];then
									echo "Preparing Yocto workdir for development build"
									SANITIZERS=y
								elif [ "production" = "${BUILDTYPE}" ];then
									echo "Preparing Yocto workdir for production build"
									DEVELOPMENT_BUILD=n
								elif [ "ccmode" = "${BUILDTYPE}" ];then
									echo "Preparing Yocto workdir for CC Mode build"
									DEVELOPMENT_BUILD=n
									CC_MODE=y
								elif [ "schsm" = "${BUILDTYPE}" ];then
									echo "Preparing Yocto workdir for ccmode build with schsm support"
									SANITIZERS=y
									ENABLE_SCHSM="1"
								else
									echo "Error, unkown BUILDTYPE, exiting..."
									exit 1
								fi

								if [ -d out-${BUILDTYPE}/conf ]; then
									rm -r out-${BUILDTYPE}/conf
								fi
								. init_ws.sh out-${BUILDTYPE}
								echo Using branch name ${BRANCH_NAME} in bbappend files
								cd ${WORKSPACE}/out-${BUILDTYPE}
								cat cmld_git.bbappend >> cmld_git.bbappend.jenkins
								rm cmld_git.bbappend
								cp cmld_git.bbappend.jenkins cmld_git.bbappend
								echo "INHERIT += \\\"own-mirrors\\\"" >> conf/local.conf
								echo "SOURCE_MIRROR_URL = \\\"file:///source_mirror/${BUILDTYPE}\\\"" >> conf/local.conf
								echo "BB_GENERATE_MIRROR_TARBALLS = \\\"0\\\"" >> conf/local.conf
								echo "SSTATE_MIRRORS =+ \\\"file://.* file:///sstate_mirror/${BUILDTYPE}/PATH\\\"" >> conf/local.conf
								echo "SSTATE_MIRRORS =+ \\\"file://.* file:///sstate_mirror/${BUILDTYPE}/PATH\\\"" >> conf/multiconfig/container.conf
								cat conf/local.conf

								if [ "ccmode" = ${BUILDTYPE} ];then
									echo "BRANCH = \\\"${BRANCH_NAME}\\\"\nEXTRA_OEMAKE += \\\"CC_MODE=y\\\"" > cmld_git.bbappend.jenkins
								fi

								echo 'TRUSTME_DATAPART_EXTRA_SPACE="10000"' >> conf/local.conf

								bitbake trustx-cml-initramfs multiconfig:container:trustx-core
								bitbake trustx-cml
							'''
						}
						post {
							success {
									script {
										if ("dev" == env.BUILDTYPE) {
											stash includes: "out-dev/tmp/deploy/images/**/trustme_image/trustmeimage.img, out-dev/test_certificates/**, trustme/build/**, trustme/cml/**", name: "img-dev"
										} else if ("production" == env.BUILDTYPE){
											stash includes: "out-production/tmp/deploy/images/**/trustme_image/trustmeimage.img, out-production/test_certificates/**, trustme/build/**, trustme/cml/**", name: "img-production"
										} else if("ccmode" == env.BUILDTYPE) {
											stash includes: "out-ccmode/tmp/deploy/images/**/trustme_image/trustmeimage.img, out-ccmode/test_certificates/**, trustme/build/**, trustme/cml/**", name: "img-ccmode"
										} else if("schsm" == env.BUILDTYPE) {
											stash includes: "out-schsm/tmp/deploy/images/**/trustme_image/trustmeimage.img, out-schsm/test_certificates/**, trustme/build/**, trustme/cml/**",name: "img-schsm"
										} else {
											error "Unkown build type"
										}
									}
									lock ('sync-mirror') {
										script {
											catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
												sh returnStatus: true, label: 'Sync source and sstate mirrors', script: '''
													if [ -z "${BUILDTYPE}" ];then
														echo "Error: BUILDTYPE not set"
														exit 1
													fi

													if [ -z "${CHANGE_TARGET}" ] && [ "dunfell" = ${BRANCH_NAME} ];then
														if ! [ -d "/sstate_mirror/${BUILDTYPE}" ];then
															echo "Error: sstate mirror directory does not exist at: /sstate_mirror/${BUILDTYPE}"
															exit 1
														fi

														echo "syncing sstate-cache"
														rsync -r out-${BUILDTYPE}/sstate-cache/ /sstate_mirror/${BUILDTYPE}
													fi


													if ! [ -d "/source_mirror/${BUILDTYPE}" ];then
														echo "Error: sstate mirror directory does not exist at: /source_mirror/${BUILDTYPE}"
														exit 1
													fi

													rsync -r out-${BUILDTYPE}/downloads/ /source_mirror/${BUILDTYPE}
												'''
											}
										}
									}
									sh label: 'Compress trustmeimage.img', script: 'xz -T 0 -f out-${BUILDTYPE}/tmp/deploy/images/**/trustme_image/trustmeimage.img --keep'

									archiveArtifacts artifacts: 'out-**/tmp/deploy/images/**/trustme_image/trustmeimage.img.xz, out-**/test_certificates/**', fingerprint: true
							}
						}
					}
				}
			}
		}

		stage ('Integration Test') {
			matrix {
				axes {
					axis {
						name 'BUILDTYPE'
						values 'dev', 'production', 'ccmode'
					}
				}
				stages {
					stage('Integration Test') {
						agent {
							node { label 'worker' }
						}

						options {
							timeout(time: 30, unit: 'MINUTES')
						}
						steps {
								cleanWs()

								script {
									if ("dev" == env.BUILDTYPE) {
										unstash 'img-dev'
									} else if ("production" == env.BUILDTYPE){
										unstash 'img-production'
									} else if ("ccmode" == env.BUILDTYPE){
										unstash 'img-ccmode'
									} else {
										error "Unkown build type"
									}
								}

								sh label: 'Perform integration tests', script: '''
									echo "Running on node $(hostname)"
									echo "$PATH"

									if [ "dev" = "${BUILDTYPE}" ];then
										echo "Testing \"dev\" image"
										bash -c '${WORKSPACE}/trustme/cml/scripts/ci/VM-container-tests.sh --skip-rootca --mode dev --dir ${WORKSPACE} --builddir out-${BUILDTYPE} --pki "${WORKSPACE}/out-${BUILDTYPE}/test_certificates" --name "qemutme-dev" --ssh 2228 --kill --vnc 41'
									elif [ "production" = "${BUILDTYPE}" ];then
										echo "Testing \"production\" image"
										bash -c '${WORKSPACE}/trustme/cml/scripts/ci/VM-container-tests.sh --skip-rootca --mode production --dir ${WORKSPACE} --builddir out-${BUILDTYPE} --pki "${WORKSPACE}/out-${BUILDTYPE}/test_certificates" --name "qemutme-pr" --ssh 2229 --kill --vnc 42'
									elif [ "ccmode" = "${BUILDTYPE}" ];then
										echo "Testing \"ccmode\" image"
										bash -c '${WORKSPACE}/trustme/cml/scripts/ci/VM-container-tests.sh --skip-rootca --mode ccmode --dir ${WORKSPACE} --builddir out-${BUILDTYPE} --pki "${WORKSPACE}/out-${BUILDTYPE}/test_certificates" --name "qemutme-cc" --ssh 2230 --kill --vnc 43'

									else
										error "Unknown build type: ${BUILDTYPE}"
									fi
								'''
						}
					}
				}
			}
		}
		stage ('Token Test') {
			agent {
				node { label 'testing' }
			}
			steps {
				sh label: 'Clean workspace', script: 'rm -fr ${WORKSPACE}/.repo ${WORKSPACE}/meta-* ${WORKSPACE}/out-* ${WORKSPACE}/trustme/build ${WORKSPACE}/poky trustme/manifest'
				unstash 'img-schsm'
				lock ('schsm-test') {
					sh label: 'Perform integration test with physical token', script: '''
						echo "Running on node $(hostname)"
						echo "$PATH"
						echo "Physhsm: ${PHYSHSM}"

						bash -c '${WORKSPACE}/trustme/cml/scripts/ci/VM-container-tests.sh --mode dev --dir ${WORKSPACE} --builddir out-schsm --pki "${WORKSPACE}/out-schsm/test_certificates" --name "qemutme-sc" --ssh 2231 --kill --enable-schsm ${PHYSHSM} 12345678'
					'''
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
