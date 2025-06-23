
module.exports = {
    title: 'Privilege Analysis',
    category: 'EKS',
    domain: 'Containers',
    severity: 'Info',
    description: 'Ensures no EKS cluster available in your AWS account is overly-permissive.',
    more_info: 'Overly-permissive EKS clusters can expose your infrastructure to unauthorized access or accidental misconfigurations. Regular analysis of permissions helps maintain a secure cluster setup.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html',
    recommended_action: 'Audit the IAM roles and policies associated with your EKS cluster. Restrict access to the minimum necessary permissions and configure security groups and endpoint access control appropriately.',
    apis: [''],
    realtime_triggers: ['eks:CreateCluster', 'eks:updateClusterConfig', 'eks:DeleteCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    }
};
