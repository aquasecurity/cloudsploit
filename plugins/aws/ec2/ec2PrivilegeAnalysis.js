module.exports = {
    title: 'Privilege Analysis',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Info',
    description: 'Check if EC2 instances are overly permissive.',
    more_info: 'EC2 instances exposed to the internet are at a higher risk of unauthorized access, data breaches, and cyberattacks. It’s crucial to limit exposure by securing access through proper configuration of security groups, NACLs, and route tables.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Security.html',
    recommended_action: 'Secure EC2 instances by restricting access with properly configured security groups and NACLs.',
    apis: [],
    realtime_triggers: ['ec2:RunInstances','ec2:TerminateInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        callback(null, results, source);

    }
};
