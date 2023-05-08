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
				script {
					REPO_NAME = determineRepoName()

					if (env.CHANGE_TARGET != null) {
						// in case this is a PR build
						// set the BASE_BRANCH to the target
						// e.g. PR-123 -> kirkstone
						BASE_BRANCH = env.CHANGE_TARGET
					} else {
						// in case this is a regular build
						// let the BASE_BRANCH equal this branch
						// e.g. kirkstone -> kirkstone
						BASE_BRANCH = BRANCH_NAME
					}
				}

				build job: "../gyroidos/${BASE_BRANCH}", wait: true, parameters: [
					string(name: "PR_BRANCHES", value: "${REPO_NAME}=${BRANCH_NAME},${PR_BRANCHES}")
				]
			}
		}
	}
}

// Determine the Repository name from its URL.
// Avoids hardcoding the name in every Jenkinsfile individually.
// Source: https://stackoverflow.com/a/45690925
String determineRepoName() {
	return scm.getUserRemoteConfigs()[0].getUrl().tokenize('/').last().split("\\.")[0]
}
