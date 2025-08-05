module.exports = {
    title: 'Privilege Analysis',
    category: 'Cloud Functions',
    domain: 'Cloud Functions',
    severity: 'Info',
    description: 'Ensures that no Cloud Functions in your cloud environment have excessive permissions.',
    more_info: 'Cloud Functions that use service accounts with excessive IAM permissions may pose security risks. It is a best practice to assign only the necessary permissions to the service accounts attached to functions.',
    link: 'https://cloud.google.com/functions/docs/securing/authenticating',
    recommended_action: 'Review and restrict the IAM roles associated with service accounts used by Cloud Functions to follow the principle of least privilege.',
    apis: [''],
    realtime_triggers: [
        'functions.CloudFunctionsService.UpdateFunction',
        'functions.CloudFunctionsService.CreateFunction',
        'functions.CloudFunctionsService.DeleteFunction'
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        callback(null, results, source);
    }
};
