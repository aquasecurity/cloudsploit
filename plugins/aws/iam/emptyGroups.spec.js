const expect = require('chai').expect;
const emptyGroups = require('./emptyGroups');

const listGroups = [
    {
        "Path": "/",
        "GroupName": "test-cp",
        "GroupId": "AGPAYE32SRU5ROTM7JUA3",
        "Arn": "arn:aws:iam::123456654321:group/test-cp",
        "CreateDate": "2020-09-20T22:20:25Z"
    },
    {
        "Path": "/",
        "GroupName": "test-cs-1",
        "GroupId": "AGPAYE32SRU5TOSRN5ZC5",
        "Arn": "arn:aws:iam::123456654321:group/test-cs-1",
        "CreateDate": "2020-09-20T22:24:49Z"
    }
];

const getGroup = [
    {
        "Users": [],
        "Group": {
            "Path": "/",
            "GroupName": "test-cp",
            "GroupId": "AGPAYE32SRU5ROTM7JUA3",
            "Arn": "arn:aws:iam::123456654321:group/test-cp",
            "CreateDate": "2020-09-20T22:20:25Z"
        }
    },
    {
        "Users": [
            {
                "Path": "/",
                "UserName": "cloudsploit",
                "UserId": "AIDAYE32SRU57PAYVNPEI",
                "Arn": "arn:aws:iam::123456654321:user/cloudsploit",
                "CreateDate": "2020-09-12T16:58:32Z",
                "PasswordLastUsed": "2020-09-20T18:58:07Z"
            }
        ],
        "Group": {
            "Path": "/",
            "GroupName": "test-cs-1",
            "GroupId": "AGPAYE32SRU5TOSRN5ZC5",
            "Arn": "arn:aws:iam::123456654321:group/test-cs-1",
            "CreateDate": "2020-09-20T22:24:49Z"
        }
    }

];

const createCache = (listGroups, getGroup) => {
    var groupName = (listGroups && listGroups.length) ? listGroups[0].GroupName : null; 
    return {
        iam: {
            listGroups: {
                'us-east-1': {
                    data: listGroups,
                },
            },
            getGroup: {
                'us-east-1': {
                    [groupName]: {
                        data: getGroup
                    }
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listGroups: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam: {
            listGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('emptyGroups', function () {
    describe('run', function () {
        it('should WARN if IAM group does not contain any users', function (done) {
            const cache = createCache([listGroups[0]], getGroup[0]);
            emptyGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should PASS if no IAM groups found', function (done) {
            const cache = createCache([]);
            emptyGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if IAM group contains user(s)', function (done) {
            const cache = createCache([listGroups[1]], getGroup[1]);
            emptyGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for IAM groups', function (done) {
            const cache = createErrorCache();
            emptyGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM groups', function (done) {
            const cache = createNullCache();
            emptyGroups.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
