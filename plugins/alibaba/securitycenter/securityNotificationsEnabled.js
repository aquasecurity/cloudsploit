var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Security Notifications Enabled',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensure that notifications are enabled for all risk items in Vulnerability, Baseline Risks, Alerts and Accesskey Leak event detection categories.',
    more_info: 'Alibaba Cloud sends notification via email, SMS or internal message whenever security events happen. ' +
        'Enable notifications for security aletrs in order to receive notifications as soon as security events happens.',
    link: 'https://www.alibabacloud.com/help/doc-detail/111648.htm',
    recommended_action: 'Enable email, SMS or internal message notifications under Security Center settings.',
    apis: ['TDS:DescribeNoticeConfig'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var securityItemsMap = {
            'yundun_security_Weekreport': 'Vulnerabilities',
            'weeklyreport': 'Baseline Risks',
            'sas_suspicious': 'Alerts',
            'yundun_aegis_AV_true': 'Precision Defense',
            'yundun_sas_ak_leakage': 'AccessKey leakage info',
            'yundun_sas_config_alert': 'Config Assessment',
            'yundun_sas_vul_Emergency': 'Emergency Vul Intelligence',
            'yundun_webguard_event': 'Anti-Tampering of web pages',
            'yundun_sas_cloud_native_firewall_Defense': 'Container firewall proactive defense notification',
            'yundun_sas_cloud_native_firewall': 'Container firewall exception alert notification',
            'yundun_IP_Blocking': 'Malicious IP interception alert'
        };

        var emailOnlyAlerts = ['yundun_IP_Blocking', 'yundun_sas_cloud_native_firewall', 'yundun_sas_cloud_native_firewall_Defense'];

        async.each(regions.tds, function(region, rcb) {
            var describeNoticeConfig = helpers.addSource(cache, source,
                ['tds', 'DescribeNoticeConfig', region]);

            if (!describeNoticeConfig) {
                return rcb();
            }

            if (describeNoticeConfig.err || !describeNoticeConfig.data) {
                helpers.addResult(results, 3,
                    `Unable to query TDS notice config: ${helpers.addError(describeNoticeConfig)}`,
                    region);
                return rcb();
            }

            if (!describeNoticeConfig.data.length) {
                helpers.addResult(results, 0, 'No TDS notice config found', region);
                return rcb();
            }

            var disabledConfigs = [];
            for (let config of describeNoticeConfig.data) {
                if ((config.Project && securityItemsMap[config.Project] && !config.Route) ||
                    (config.Project && emailOnlyAlerts.includes(config.Project) && (!config.Route || config.Route == 5)))
                    disabledConfigs.push(securityItemsMap[config.Project]);
            }

            if (disabledConfigs.length) {
                helpers.addResult(results, 2,
                    `Security notifications are not enabled for: ${disabledConfigs.join(', ')}`, region);
            } else {
                helpers.addResult(results, 0,
                    'Security notifications are enabled for all alerts', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};