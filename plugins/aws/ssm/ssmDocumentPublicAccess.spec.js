const expect  = require('chai').expect;
const ssmDocumentPublicAccess = require('./ssmDocumentPublicAccess');

const serviceSetting = [
    {
        "SettingId": "/ssm/documents/console/public-sharing-permission",
        "SettingValue": "Enable",
        "LastModifiedDate": "2021-09-04T20:34:24.668000+00:00",
        "LastModifiedUser": "arn:aws:iam::000111222333:user/umair",
        "ARN": "arn:aws:ssm:us-east-1:000111222333:servicesetting/ssm/documents/console/public-sharing-permission",
        "Status": "Customized" 
    },
    {
        "SettingId": "/ssm/documents/console/public-sharing-permission",
        "SettingValue": "Disable",
        "LastModifiedDate": "2021-09-04T20:34:24.668000+00:00",
        "LastModifiedUser": "arn:aws:iam::000111222333:user/umair",
        "ARN": "arn:aws:ssm:us-east-1:000111222333:servicesetting/ssm/documents/console/public-sharing-permission",
        "Status": "Customized" 
    },
    {
        "SettingId": "/ssm/documents/console/public-sharing-permission",
        "LastModifiedDate": "2021-09-04T20:34:24.668000+00:00",
        "LastModifiedUser": "arn:aws:iam::000111222333:user/umair",
        "ARN": "arn:aws:ssm:us-east-1:000111222333:servicesetting/ssm/documents/console/public-sharing-permission",
        "Status": "Customized" 
    }
]

const createCache = (serviceSetting) => {
    return {
        ssm:{
            getServiceSetting: {
                'us-east-1': {
                    data: serviceSetting
                }
            }
        }
    }
}

const createErrorCache = () => {
  return {
      ssm:{
        getServiceSetting: {
              'us-east-1': {
                  err: {
                      message: 'error describing SSM service settings'
                  },
              },
          }
      },
  };
};

const createNullCache = () => {
  return {
      ssm:{
        getServiceSetting: {
              'us-east-1': null,
          },
      },
  };
};

describe('ssmDocumentPublicAccess', function () {
  describe('run', function () {
      it('should PASS if SSM service has block public sharing is disabled', function (done) {
          const cache = createCache(serviceSetting[1]);
          ssmDocumentPublicAccess.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(1);
              expect(results[0].status).to.equal(0);
              expect(results[0].message).to.include('SSM service has block public sharing disabled');
              expect(results[0].region).to.equal('us-east-1');
              done();
            });
        });

        it('should FAIL if SSM service has block public sharing is enabled', function (done) {
            const cache = createCache(serviceSetting[0]);
            ssmDocumentPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SSM service has block public sharing enabled for SSM documents');
                expect(results[0].region).to.equal('us-east-1');
              done();
          });
        });

        it('should UNKNOWN if unable to query for SSM service settings', function (done) {
          const cache = createErrorCache();
          ssmDocumentPublicAccess.run(cache, {}, (err, results) => {
            expect(results.length).to.equal(1);
            expect(results[0].status).to.equal(3);
            expect(results[0].region).to.equal('us-east-1');
            done();
          });
        });

      it('should not return anything if get service setting response not found', function (done) {
          const cache = createNullCache();
          ssmDocumentPublicAccess.run(cache, {}, (err, results) => {
              expect(results.length).to.equal(0);
              done();
          });
      });

  });
});