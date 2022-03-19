var expect = require('chai').expect;
const compliantLifecyleConfigured = require('./compliantLifecyleConfigured');

const listBackupPlans = [
    {
        "BackupPlanArn": "arn:aws:backup:us-east-1:000011112222:backup-plan:07ade659-ed39-4a80-a62c-267828ca315a",
        "BackupPlanId": "07ade659-ed39-4a80-a62c-267828ca315a",
        "CreationDate": "2022-01-21T16:19:55.937000+05:00",
        "VersionId": "YTY2NGEzZjMtODQxZC00OTlhLTg0MTYtODQ3NWNhNjg3NWUz",
        "BackupPlanName": "mine1"
    },
    {
        "BackupPlanArn": "arn:aws:backup:us-east-1:000011112222:backup-plan:07ade659-ed39-4a80-a62c-267828ca325a",
        "BackupPlanId": "07ade659-ed39-4a80-a62c-267828ca315a",
        "CreationDate": "2022-01-21T16:19:55.937000+05:00",
        "VersionId": "YTY2NGEzZjMtODQxZC00OTlhLTg0MTYtODQ3NWNhNjg3NWUx",
        "BackupPlanName": "mine2"
    }
];

const getBackupPlan = [
    {
        "BackupPlan": {
            "BackupPlanName": "mine1",
            "Rules": [
                {
                    "RuleName": "DailyBackups",
                    "TargetBackupVaultName": "Default",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                    "StartWindowMinutes": 480,
                    "CompletionWindowMinutes": 10080,
                    "Lifecycle": {
                        "DeleteAfterDays": 35,
                        "MoveToColdStorageAfterDays": 120
                    },
                    "RuleId": "5e0a4936-0da8-4455-a63c-c63ec62e1474"
                }
            ]
        },
        "BackupPlanId": "07ade659-ed39-4a80-a62c-267828ca315a",
        "BackupPlanArn": "arn:aws:backup:us-east-1:000011112222:backup-plan:07ade659-ed39-4a80-a62c-267828ca315a",
        "VersionId": "YTY2NGEzZjMtODQxZC00OTlhLTg0MTYtODQ3NWNhNjg3NWUz",
        "CreationDate": "2022-01-21T16:19:55.937000+05:00"
    },
    {
        "BackupPlan": {
            "BackupPlanName": "mine1",
            "Rules": [
                {
                    "RuleName": "DailyBackups",
                    "TargetBackupVaultName": "Default",
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                    "StartWindowMinutes": 480,
                    "CompletionWindowMinutes": 10080,
                    "Lifecycle": {
                        "DeleteAfterDays": null,
                        "MoveToColdStorageAfterDays": null
                    },
                    "RuleId": "5e0a4936-0da8-4455-a63c-c63ec62e1474"
                }
            ]
        },
        "BackupPlanId": "07ade659-ed39-4a80-a62c-267828ca325a",
        "BackupPlanArn": "arn:aws:backup:us-east-1:000011112222:backup-plan:07ade659-ed39-4a80-a62c-267828ca325a",
        "VersionId": "YTY2NGEzZjMtODQxZC00OTlhLTg0MTYtODQ3NWNhNjg3NWUx",
        "CreationDate": "2022-01-21T16:19:55.937000+05:00"
    }
];


const createCache = (plans, getBackupPlan, plansErr, getBackupPlanErr) => {
    var id = (plans && plans.length) ? plans[0].BackupPlanId : null;
    return {
        backup: {
            listBackupPlans: {
                'us-east-1': {
                    data: plans,
                    err: plansErr
                },
            },
            getBackupPlan: {
                'us-east-1': {
                    [id]: {
                        data: getBackupPlan,
                        err: getBackupPlanErr
                    }
                }
            }
        },
    }
}

describe('compliantLifecyleConfigured', function () {
    describe('run', function () {
        it('should PASS if Backup plan has lifecycle configuration enabled', function (done) {
            const cache = createCache([listBackupPlans[0]], getBackupPlan[0]);
            compliantLifecyleConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup plan has lifecycle configuration enabled')
                done();
            });
        });

        it('should FAIL if Backup plan does not have lifecycle configuration enabled', function (done) {
            const cache = createCache([listBackupPlans[1]], getBackupPlan[1]);
            compliantLifecyleConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Backup plan does not have lifecycle configuration enabled')
                done();
            });
        });

        it('should PASS if no Backup plans found', function (done) {
            const cache = createCache([]);
            compliantLifecyleConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Backup plans found')
                done();
            });
        });

        it('should UNKNOWN if Unable to list Backup plans', function (done) {
            const cache = createCache(null, null, { message: "Unable to list Backup plans" });
            compliantLifecyleConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list Backup plans')
                done();
            });
        });
    });
})