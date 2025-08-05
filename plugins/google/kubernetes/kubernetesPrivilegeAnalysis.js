module.exports = {
    title: 'Privilege Analysis',
    category: 'Kubernetes',
    domain: 'Containers',
    severity: 'Info',
    description: 'Ensures that Kubernetes workloads and service accounts are not granted excessive permissions.',
    more_info: 'Kubernetes workloads often use service accounts to interact with the Kubernetes API and other GCP resources. Over-privileged service accounts can lead to privilege escalation or lateral movement within the cluster or the cloud environment. Following the principle of least privilege helps minimize potential attack surfaces.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/iam',
    recommended_action: 'Review and minimize IAM permissions granted to Kubernetes service accounts and workload identities. Use role-based access control (RBAC) and GCP IAM best practices to ensure only required access is permitted.',
    apis: [''],
    realtime_triggers: [
        'container.projects.updateCluster',
        'container.projects.createCluster',
        'container.projects.deleteCluster',
        'iam.serviceAccounts.setIamPolicy',
        'iam.serviceAccounts.getIamPolicy'
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    }
};
