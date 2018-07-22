var async   = require('async');
var helpers = require('../../helpers');
var config  = require('../../../../config/db.js');
var db 		= require('../../../../models');

module.exports = {
    title: 'EC2 Approved Instance Types',
    category: 'EC2',
    description: 'Ensures that running EC2 instances are within the approved types setting.',
    more_info: 'The types of EC2 instances should be carefully audited, to ensure only approved types are launched and consuming compute resources. Many compromised AWS accounts see large EC2 instances launched without approval and overrun costs.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html',
    recommended_action: 'Ensure that the EC2 instances types match the approved types. If instances are launched that do not belong to the approved types, investigate to ensure they are legitimate.',
    apis: ['EC2:describeInstances'],
    settings: {
        disapproved_instance_types_global: {
            name: 'Disapproved Instance Types Global',
            description: 'Checks for unapproved instances across all regions and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_east_1: {
            name: 'Disapproved Instance Types Region: us-east-1',
            description: 'Checks for unapproved instances in the us-east-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_east_2: {
            name: 'Disapproved Instance Types Region: us-east-2',
            description: 'Checks for unapproved instances in the us-east-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_west_1: {
            name: 'Disapproved Instance Types Region: us-west-1',
            description: 'Checks for unapproved instances in the us-west-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_us_west_2: {
            name: 'Disapproved Instance Types Region: us-west-2',
            description: 'Checks for unapproved instances in the us-west-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_northeast_1: {
            name: 'Disapproved Instance Types Region: ap-northeast-1',
            description: 'Checks for unapproved instances in the ap-northeast-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_northeast_2: {
            name: 'Disapproved Instance Types Region: ap-northeast-2',
            description: 'Checks for unapproved instances in the ap-northeast-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_southeast_1: {
            name: 'Disapproved Instance Types Region: ap-southeast-1',
            description: 'Checks for unapproved instances in the ap-southeast-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_southeast_2: {
            name: 'Disapproved Instance Types Region: ap-southeast-2',
            description: 'Checks for unapproved instances in the ap-southeast-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_central_1: {
            name: 'Disapproved Instance Types Region: eu-central-1',
            description: 'Checks for unapproved instances in the eu-central-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_1: {
            name: 'Disapproved Instance Types Region: eu-west-1',
            description: 'Checks for unapproved instances in the eu-west-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_2: {
            name: 'Disapproved Instance Types Region: eu-west-2',
            description: 'Checks for unapproved instances in the eu-west-2 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_eu_west_3: {
            name: 'Disapproved Instance Types Region: eu-west-3',
            description: 'Checks for unapproved instances in the eu-west-3 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_sa_east_1: {
            name: 'Disapproved Instance Types Region: sa-east-1',
            description: 'Checks for unapproved instances in the sa-east-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ap_south_1: {
            name: 'Disapproved Instance Types Region: ap-south-1',
            description: 'Checks for unapproved instances in the ap-south-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        },
        disapproved_instance_types_region_ca_central_1: {
            name: 'Disapproved Instance Types Region: ca-central-1',
            description: 'Checks for unapproved instances in the ca-central-1 region and triggers a failing result if any are found',
            regex: '([a-zA-Z0-9.])',
            default: 'cc2.8xlarge,hs1.8xlarge,m5.12xlarge,m5.24xlarge,m4.10xlarge,m4.16xlarge,c5.9xlarge,c5.18xlarge,c4.8xlarge,r4.8xlarge,r4.16xlarge,p3.8xlarge,p3.16xlarge,p2.8xlarge,p2.16xlarge,g3.8xlarge,g3.16xlarge,h1.8xlarge,h1.16xlarge,d2.8xlarge,c3.8xlarge,g2.8xlarge,cr1.8xlarge,x1.16xlarge,x1.32xlarge,x1e.8xlarge,x1e.16xlarge,x1e.32xlarge,r3.8xlarge,i2.8xlarge,m5d.12xlarge,m5d.24xlarge,c5d.9xlarge,c5d.18xlarge,f1.16xlarge,i3.8xlarge,i3.16xlarge,i3.metal'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            disapproved_instance_types_global: settings.disapproved_instance_types_global || this.settings.disapproved_instance_types_global,
            disapproved_instance_types_region_us_east_1: settings.disapproved_instance_types_region_us_east_1 || this.settings.disapproved_instance_types_region_us_east_1,
            disapproved_instance_types_region_us_east_2: settings.disapproved_instance_types_region_us_east_2 || this.settings.disapproved_instance_types_region_us_east_2,
            disapproved_instance_types_region_us_west_1: settings.disapproved_instance_types_region_us_west_1 || this.settings.disapproved_instance_types_region_us_west_1,
            disapproved_instance_types_region_us_west_2: settings.disapproved_instance_types_region_us_west_2 || this.settings.disapproved_instance_types_region_us_west_2,
            disapproved_instance_types_region_ap_northeast_1: settings.disapproved_instance_types_region_ap_northeast_1 || this.settings.disapproved_instance_types_region_ap_northeast_1,
            disapproved_instance_types_region_ap_northeast_2: settings.disapproved_instance_types_region_ap_northeast_2 || this.settings.disapproved_instance_types_region_ap_northeast_2,
            disapproved_instance_types_region_ap_southeast_1: settings.disapproved_instance_types_region_ap_southeast_1 || this.settings.disapproved_instance_types_region_ap_southeast_1,
            disapproved_instance_types_region_ap_southeast_2: settings.disapproved_instance_types_region_ap_southeast_2 || this.settings.disapproved_instance_types_region_ap_southeast_2,
            disapproved_instance_types_region_eu_central_1: settings.disapproved_instance_types_region_eu_central_1 || this.settings.disapproved_instance_types_region_eu_central_1,
            disapproved_instance_types_region_eu_west_1: settings.disapproved_instance_types_region_eu_west_1 || this.settings.disapproved_instance_types_region_eu_west_1,
            disapproved_instance_types_region_eu_west_2: settings.disapproved_instance_types_region_eu_west_2 || this.settings.disapproved_instance_types_region_eu_west_2,
            disapproved_instance_types_region_eu_west_3: settings.disapproved_instance_types_region_eu_west_3 || this.settings.disapproved_instance_types_region_eu_west_3,
            disapproved_instance_types_region_sa_east_1: settings.disapproved_instance_types_region_sa_east_1 || this.settings.disapproved_instance_types_region_sa_east_1,
            disapproved_instance_types_region_ap_south_1: settings.disapproved_instance_types_region_ap_south_1 || this.settings.disapproved_instance_types_region_ap_south_1,
            disapproved_instance_types_region_ca_central_1: settings.disapproved_instance_types_region_ca_central_1 || this.settings.disapproved_instance_types_region_ca_central_1
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var instance_count = 0;
        var instance_count_global_threshold = 0;
        var my_test_id = 0;

        db.test.findOne({
            attributes: ['id'],
            where: {
                title: 'EC2 Approved Instance Types'
            }
        }).then(function(test){
            if (!test) {
                console.log('Not found')
            } else {
                my_test_id = test.id;
                db.customization.destroy({
                    where: {
                        test_id: test.id
                    }
                }).then(function(deletedCustomizations){
                    console.log('Has the Customization been deleted? 1 means yes, 0 means no: ' + deletedCustomizations.toString());
                });
            }

            helpers.regions.ec2.forEach(function(region){

                var customizationConfig = eval('config.disapproved_instance_types_region_'+region.replace(new RegExp('-','g'),'_').toString());

                var customizationBuild = db.customization.build({
                    setting: 'disapproved_instance_types_region_'+region.replace(new RegExp('-','g'),'_').toString(),
                    default: customizationConfig.default.toString(),
                    name: customizationConfig.name,
                    description: customizationConfig.description,
                    regex: customizationConfig.regex,
                    created: new Date(new Date() -  60 * 1000 * config.REALTIME_DESCRIBE_EXPIRATION),
                    test_id: my_test_id
                });

                customizationBuild.save().then(function(savedCustomization){
                    console.log(('Created: ' + savedCustomization.id.toString()));
                });
            });

            var customizationConfig = eval('config.disapproved_instance_types_global');

            var customizationBuild = db.customization.build({
                setting: 'disapproved_instance_types_global',
                default: customizationConfig.default.toString(),
                name: customizationConfig.name,
                description: customizationConfig.description,
                regex: customizationConfig.regex,
                created: new Date(new Date() -  60 * 1000 * config.REALTIME_DESCRIBE_EXPIRATION),
                test_id: my_test_id
            });

            customizationBuild.save().then(function(savedCustomization){
                console.log(('Created: ' + savedCustomization.id.toString()));
            });

        }, null);
    }
};
