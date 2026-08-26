/*
 * Approve the pipeline script defined by Configuration as Code.
 *
 * A job created from casc.yaml runs outside the Groovy sandbox, so Jenkins
 * holds its script for manual admin approval and the first build fails with
 * UnapprovedUsageException. Clicking "approve" in the UI defeats the point of
 * an automated setup, so any script pending at startup is approved here.
 *
 * This is safe in this deployment because the only scripts that can be
 * pending are the ones shipped in this repository - the instance is not
 * multi-tenant and does not accept jobs from untrusted users.
 */
import org.jenkinsci.plugins.scriptsecurity.scripts.ScriptApproval

def approval = ScriptApproval.get()
def pending = approval.pendingScripts

if (pending.isEmpty()) {
    println '[init] no pending script approvals'
} else {
    pending.each { script ->
        approval.approveScript(script.getHash())
        println "[init] approved pipeline script ${script.getHash()}"
    }
    approval.save()
}
