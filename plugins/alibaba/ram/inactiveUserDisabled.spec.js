var expect = require('chai').expect;
var helpers = require('../../../helpers/alibaba');
var inactiveUserDisabled = require('./inactiveUserDisabled')

const currentDate = new Date();
const listUsers = [
    {
        "UserName": "aqua",
        "UserId": "254529020129829608",
    },
    {
        "UserName": "cloudsploit",
        "UserId": "283806919721151694",
    }
];

const getUserData = [
    {
		"UserName": "aqua",
		"UserId": "214008820731498041",
		"LastLoginDate": "2021-01-13T02:11:29Z",
		"CreateDate": "2021-05-11T11:11:38Z",
	},
    {
		"UserName": "cloudsploit",
		"UserId": "214008820731498041",
		"LastLoginDate": "2021-05-13T02:11:29Z",
		"CreateDate": "2021-05-11T11:11:38Z",
	}
];

const getUserLoginProfile = [
    {
        "LoginProfile": {
            "UserName": "aqua",
        }
    },
    {
        "RequestId": "1AE50527-F715-4F01-AE7D-64463D920B3D",
    }
];

const createCache = (users, userData, userProfile, userProfileError, error) => {
    let userName = (users && users.length) ? users[0].UserName : null;
    return {
        ram: {
            ListUsers: {
                'cn-hangzhou': {
                    data: users,
                    err: error
                }
            },
            GetUser: {
                'cn-hangzhou': {
                    [userName]: {
                        data: userData,
                        err: error
                    }
                }
            },
            GetLoginProfile: {
                'cn-hangzhou': {
                    [userName]: {
                        data: userProfile,
                        err: userProfileError
                    }
                }
            },
        }
    }
}

describe('inactiveUserDisabled', function () {
    describe('run', function () {
        it('should FAIL if RAM user is enabled on being inactive for 90 or more days', function (done) {
            const loginDate = new Date(getUserData[0].LastLoginDate);
            const diffInDays = helpers.daysBetween(currentDate, loginDate);
            const cache = createCache([listUsers[0]], getUserData[0], getUserLoginProfile[0], null, null);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include(`RAM user inactive for ${diffInDays} days is enabled`);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should PASS if RAM user is disabled on being inactive for 90 or more days', function (done) {
            const loginDate = new Date(getUserData[0].LastLoginDate);
            const diffInDays = helpers.daysBetween(currentDate, loginDate);
            const cache = createCache([listUsers[0]], getUserData[0], getUserLoginProfile[1], {Code : 'EntityNotExist.User.LoginProfile'}, null);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include(`RAM user inactive for ${diffInDays} days is not enabled`);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should PASS if RAM user last activity was before 90 days', function (done) {
            const loginDate = new Date(getUserData[1].LastLoginDate);
            const diffInDays = helpers.daysBetween(currentDate, loginDate);
            const cache = createCache([listUsers[1]], getUserData[1], getUserLoginProfile[0], null, null);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include(`RAM user last activity was ${diffInDays} days ago`);
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should PASS if No RAM users found', function (done) {
            const cache = createCache([]);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No RAM users found');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should UNKNOWN if Unable to query login profile', function (done) {
            const cache = createCache([listUsers[0]], getUserData[0], getUserLoginProfile[0], {}, null);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query user login profile');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
        it('should UNKNOWN if Unable to query RAM users', function (done) {
            const cache = createCache(null, null, null, null);
            inactiveUserDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query RAM users');
                expect(results[0].region).to.equal('cn-hangzhou');
                done();
            });
        });
    })
})
