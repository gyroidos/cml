pipeline {
	agent any

	options {
		preserveStashes(buildCount: 1) 
	}

	parameters {
		string(name: 'PR_BRANCHES', defaultValue: '', description: 'Comma separated list of additional pull request branches (e.g. meta-trustx=PR-177,meta-trustx-nxp=PR-13,gyroidos_build=PR-97)')
		string(name: 'CI_LIB_VERSION', defaultValue: 'main', description: 'Version of the gyroidos_ci_common library to be used, e.g. pull/17/head for PR-17 on gyroidos_ci_common')
	}

	stages {
		stage('build GyroidOS') {
			parallel {
				stage('build x86') {
					steps {
						script {
							REPO_NAME = determineRepoName()
							BASE_BRANCH = determineBaseBranch()
						}

						build job: "../gyroidos/${BASE_BRANCH}", wait: true, parameters: [
							string(name: "PR_BRANCHES", value: "${REPO_NAME}=${env.BRANCH_NAME},${env.PR_BRANCHES}"),
							string(name: "CI_LIB_VERSION", value: "${CI_LIB_VERSION}"),
							string(name: "GYROID_ARCH", value: "x86"),
							string(name: "GYROID_MACHINE", value: "genericx86-64")
						]
					}
				}

				stage('build arm64') {
					steps {
						script {
							REPO_NAME = determineRepoName()
							BASE_BRANCH = determineBaseBranch()
						}

						build job: "../gyroidos/${BASE_BRANCH}", wait: true, parameters: [
							string(name: "PR_BRANCHES", value: "${REPO_NAME}=${env.BRANCH_NAME},${env.PR_BRANCHES}"),
							string(name: "CI_LIB_VERSION", value: "${CI_LIB_VERSION}"),
							string(name: "GYROID_ARCH", value: "arm64"),
							string(name: "GYROID_MACHINE", value: "tqma8mpxl")
						]
					}
				}
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

String determineBaseBranch() {
	if (env.CHANGE_TARGET != null) {
		// in case this is a PR build
		// set the BASE_BRANCH to the target
		// e.g. PR-123 -> kirkstone
		return env.CHANGE_TARGET
	} else {
		// in case this is a regular build
		// let the BASE_BRANCH equal this branch
		// e.g. kirkstone -> kirkstone
		return env.BRANCH_NAME
	}
}
