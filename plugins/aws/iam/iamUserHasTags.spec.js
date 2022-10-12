const expect = require('chai').expect;
const iamUserHasTags = require('./iamUserHasTags.js');

const listUsers = [
    {
        "Path": "/",
        "UserName": "cloudsploit",
        "UserId": "AIDARPGOCGXSSUH7TNLM4",
        "Arn": "arn:aws:iam::000011111:user/cloudsploit",
        "CreateDate": "2021-12-12T13:15:54+00:00"
    },
    { 
        "Path": "/",
        "UserName": "testUser",
        "UserId": "AIDARPGOCGXSUSX63OQEM",
        "Arn": "arn:aws:iam::0000111111112:user/testUser",
        "CreateDate": "2022-10-10T11:41:15+00:00"
    }
];

const getUser = [
    {
        "User": {
            "Path": "/",
            "UserName": "cloudsploit",
            "UserId": "AIDARPGOCGXSSUH7TNLM4",
            "Arn": "arn:aws:iam::000011111:user/cloudsploit",
            "CreateDate": "2021-12-12T13:15:54+00:00",
            "Tags": [
                {
                    "Key": "tag",
                    "Value": "tag"
                }
            ]
        }
    },
    {
        "User": {
            "Path": "/",
            "UserName": "testUser",
            "UserId": "AIDARPGOCGXSUSX63OQEM",
            "Arn": "arn:aws:iam::0000111111112:user/testUser",
            "CreateDate": "2022-10-10T11:41:15+00:00",
        }
    }
]
const createCache = (listUsers,getUser) => {
    var userName = (listUsers && listUsers.length) ? listUsers[0].UserName : null; 
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    data: listUsers,
                    err: null
                },
            },
            getUser: {
                'us-east-1': {
                    [userName]:{   
                        data: getUser,
                        err: null    
                    }              
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            listUsers: {
                'us-east-1': {
                    err: {
                        message: 'error listing IAM users'
                    },
                },
            },
        },
    };
};

describe('iamUserHasTags', function () {
    describe('run', function () {
        it('Should PASS if IAM user has tags', function (done) {
            const cache = createCache([listUsers[0]],getUser[0]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('IAM User has tags');
                done();
            });
        });

        it('Should FAIL if IAM user has tags', function (done) {
            const cache = createCache([listUsers[1]],getUser[1]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('IAM User does not have tags');
                done();
            });
        });
        
        it('Should UNKNOWN if error in listing IAM user', function (done) {
            const cache = createErrorCache();
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('Should PASS if no IAM user found', function (done) {
            const cache = createCache([]);
            iamUserHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

    });
});