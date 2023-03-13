pipeline {
	agent any

	parameters {
		string(name: 'PR_BRANCHES', defaultValue: '', description: 'Comma separated list of additional pull request branches (e.g. meta-trustx=PR-177,meta-trustx-nxp=PR-13,gyroidos_build=PR-97)')
	}

	stages {
		stage('Inspect the Codebase') {
			parallel {
				stage('Code Format & Style') {
					agent {
						dockerfile {
							/*TODO: update the Dockerfile in the build repo instead*/
							dir 'scripts/ci'
							args '--entrypoint=\'\' -v /yocto_mirror:/source_mirror'
						}
					}

					steps {
						sh label: 'Clean cml Repo', script: '''
							cd ${WORKSPACE}
							git clean -fx
						'''
						sh label: 'Check code formatting', script: 'scripts/ci/check-if-code-is-formatted.sh'
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
					dir 'scripts/ci'
					args '--entrypoint=\'\''
					reuseNode true
				}
			}

			steps {
				sh label: 'Clean cml Repo', script: '''
					cd ${WORKSPACE}
					git clean -fx
				'''
				sh label: 'Perform unit tests', script: 'scripts/ci/unit-testing.sh'
			}
		}

		stage('build GyroidOS') {
			steps {
				build job: "../gyroidos/kirkstone", wait: true, parameters: [
					string(name: "PR_BRANCHES", value: "cml=${BRANCH_NAME},${PR_BRANCHES}")
				]
			}
		}
	}
}
