var expect = require('chai').expect;
var backupResourceProtection = require('./backupResourceProtection');

const describeRegionSettings = [
    {
        "Aurora": true,
        "DocumentDB": true,
        "DynamoDB": true,
        "EBS": true,
        "EC2": true,
        "EFS": true,
        "FSx": true,
        "Neptune": true,
        "RDS": true,
        "Storage Gateway": true,
        "VirtualMachine": false
    },
    {
        "Aurora": true,
        "DocumentDB": false,
        "DynamoDB": false,
        "EBS": true,
        "EC2": false,
        "EFS": true,
        "FSx": true,
        "Neptune": true,
        "RDS": true,
        "Storage Gateway": true,
        "VirtualMachine": true
    }
];

const createCache = (resource, resourceErr) => {
    return {
        backup: {
            describeRegionSettings: {
                'us-east-1': {
                    err: resourceErr,
                    data: resource
                },
            },
        },
    };
};

describe('backupResourceProtection', function () {
    describe('run', function () {
        it('should PASS if Backup configuration for protected resource types is compliant', function (done) {
            const cache = createCache([describeRegionSettings[1]]);
            backupResourceProtection.run(cache, { backup_resource_type:'rds, efs, aurora, dynamodb, storage gateway, ec2, ebs, virtual machine'}, (err, results) => {
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Backup configuration for protected resource types is compliant');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Backup configuration for protected resource types is not compliant', function (done) {
            const cache = createCache(describeRegionSettings[0]);
            backupResourceProtection.run(cache, { backup_resource_type:'rds, efs, aurora, dynamodb, storage gateway, ec2, ebs, virtual machine'}, (err, results) =>{
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Backup configuration for protected resource types is not compliant');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN Unable to query for Backup resource type opt in preference', function (done) {
            const cache = createCache(null, { message: "Unable to query for Backup resource type opt in preference" });
            backupResourceProtection.run(cache, { backup_resource_type: 'rds, efs, aurora, dynamodb, storage gateway, ec2, ebs, virtual machine'}, (err, results) => {
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
}); 