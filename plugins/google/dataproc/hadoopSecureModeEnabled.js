var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Hadoop Secure Mode Enabled',
    category: 'Dataproc',
    domain: 'Compute',
    description: 'Ensure that all Dataproc clusters have hadoop secure mode enabled.',
    more_info: 'Enabling Hadoop secure mode will allow multi-tenancy with security features like isolation, encryption, and user authentication within the cluster. It also enforces all Hadoop services and users to be authenticated via Kerberos Key distribution.',
    link: 'https://cloud.google.com/dataproc/docs/concepts/configuring-clusters/security',
    recommended_action: 'Enable Hadoop secure mode for all Dataproc clusters.',
    apis: ['dataproc:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.dataproc, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['dataproc' ,'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Dataproc clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Dataproc clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {

                if (!cluster.clusterName) return;

                let resource = helpers.createResourceName('clusters', cluster.clusterName, project, 'region', region);

                if (cluster.config && cluster.config.securityConfig
                        && cluster.config.securityConfig.kerberosConfig && cluster.config.securityConfig.kerberosConfig.enableKerberos) {
                    helpers.addResult(results, 0,
                        'Hadoop Secure mode is enabled for Dataproc cluster', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Hadoop Secure mode is not enabled for Dataproc cluster', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};