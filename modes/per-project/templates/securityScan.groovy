// Jenkins shared-library step: put this file at vars/securityScan.groovy in your shared library repo,
// then in any Jenkinsfile:   securityScan()                          // uses .security/config.env
//                            securityScan(enforce: true, gate: 'release', image: env.IMAGE)
def call(Map cfg = [:]) {
    def cmd = cfg.enforce ? 'gate' : 'scan'
    def gate = cfg.gate ?: 'pr'
    def args = "--gate ${gate}" + (cfg.image ? " --image ${cfg.image}" : '') + (cfg.zapUrl ? " --zap-url ${cfg.zapUrl}" : '')
    try {
        sh ".security/secscan ${cmd} ${args}"
    } finally {
        archiveArtifacts artifacts: '.security/reports/20*/summary.html, .security/reports/20*/summary.md', allowEmptyArchive: true
    }
}
