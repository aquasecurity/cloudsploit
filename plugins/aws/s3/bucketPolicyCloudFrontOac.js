var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Policy CloudFront OAC',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensures S3 bucket is origin to only one distribution and allows only that distribution.',
    more_info: 'Access to CloudFront origins should only happen via ClouFront URL and not from S3 URL or any source in order to restrict access to private data.',
    link: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html',
    recommended_action: 'Review the access policy for S3 bucket which is an origin to a CloudFront distribution. Make sure the S3 bucket is origin to only one distribution. ' +
        'Modify the S3 bucket access policy to allow CloudFront OAC for only the associated CloudFront distribution and restrict access from any other source.',
    apis: ['CloudFront:listDistributions', 'S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketLocation', 'STS:getCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires that access to protected information is controlled and audited. ' +
                'If an S3 bucket backing a CloudFront distribution does not require the end ' +
                'user to access the contents through CloudFront, this policy may be violated.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings); 
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);

        var listDistributions = helpers.addSource(cache, source,
            ['cloudfront', 'listDistributions', region]);

        if (!listDistributions) return callback(null, results, source);

        if (listDistributions.err || !listDistributions.data) {
            helpers.addResult(results, 3,
                'Unable to query for CloudFront distributions: ' + helpers.addError(listDistributions));
            return callback(null, results, source);
        }

        if (!listDistributions.data.length) {
            helpers.addResult(results, 0, 'No S3 origins to check');
            return callback(null, results, source);
        }

        var s3OriginFound = false;
        var s3BucketAssociations = {};
        listDistributions.data.forEach(distribution => {
            if (distribution.Id &&
                distribution.DomainName &&
                distribution.DomainName.length &&
                distribution.Origins &&
                distribution.Origins.Items &&
                distribution.Origins.Items.length) {
                for (let origin of distribution.Origins.Items) {
                    if (!origin.DomainName) continue;
                    let cfUser;
                    let bucketName = origin.DomainName.replace(/.s3.*.com/, '');
                    
                    if (origin.OriginAccessControlId && origin.OriginAccessControlId.length) {
                        cfUser = `arn:aws:cloudfront::${accountId}:distribution/${distribution.Id}`;
                        createAssociation(s3BucketAssociations, bucketName, distribution.Id, cfUser);
                        s3BucketAssociations[bucketName][distribution.Id].OACfound = true;
                        s3OriginFound = true;
                    } else if (origin.S3OriginConfig && 
                                    origin.S3OriginConfig.OriginAccessIdentity &&
                                    origin.S3OriginConfig.OriginAccessIdentity.length) {
                        let oaiId = origin.S3OriginConfig.OriginAccessIdentity.substring(origin.S3OriginConfig.OriginAccessIdentity.lastIndexOf('/') + 1);
                        cfUser = `arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${oaiId}`;
                        createAssociation(s3BucketAssociations,bucketName,distribution.Id,cfUser);
                        s3OriginFound = true;
                    } else {
                        s3BucketAssociations[bucketName] = {};
                        s3BucketAssociations[bucketName][distribution.Id] = [];
                        s3BucketAssociations[bucketName][distribution.Id].OACfound = false;
                    }

                }
            }
        });

        if (!s3OriginFound) {
            helpers.addResult(results, 0, 'No S3 origins found for CloudFront distributions');
            return callback(null, results, source);
        }

        async.each(Object.entries(s3BucketAssociations), function([bucketName, cfDistributions], cb){
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucketName);

            if (Object.keys(cfDistributions).length > 1) {
                helpers.addResult(results, 2,
                    `S3 bucket is origin to more than one distributions which are these: ${Object.keys(cfDistributions).join(', ')}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var distributionId = Object.keys(cfDistributions).toString();
            if (!s3BucketAssociations[bucketName][distributionId].OACfound) {
                helpers.addResult(results, 2,
                    `S3 bucket is origin to distribution "${distributionId}" without an Origin Access Control`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucketName]);
            if (getBucketPolicy && getBucketPolicy.err &&
                    getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2,
                    `No bucket policy found for S3 bucket: ${bucketName}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }
            
            if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    `Error querying for bucket policy for bucket "${bucketName}": ${helpers.addError(getBucketPolicy)}`,
                    bucketLocation, `arn:aws:s3:::${bucketName}`);
                return cb();
            }

            var statements = helpers.normalizePolicyDocument(getBucketPolicy.data.Policy);

            if (!statements || !statements.length) return cb();

            var unknownConditions = [];
            var restrictedOrigins = [];
            var allowedOrigins = [];
            var allowedConditions = ['aws:PrincipalArn','aws:PrincipalAccount','aws:PrincipalOrgID','aws:SourceAccount','aws:SourceArn','aws:SourceOwner'];

            for (var statement of statements) {     
                var conditions = (statement.Condition)? helpers.isValidCondition(statement, allowedConditions, helpers.IAM_CONDITION_OPERATORS, 'ture').flat() : [];
                var principals = helpers.extractStatementPrincipals(statement).toString;
                if (principals.length) conditions.push(principals);

                for (var condition of conditions) {
                    if (statement.Effect &&
                                    statement.Effect.toUpperCase() === 'ALLOW' &&
                                    !(s3BucketAssociations[bucketName][distributionId].includes(condition)) &&   
                                    !unknownConditions.includes(condition)) {
                        unknownConditions.push(condition);
                    }

                    if (statement.Effect &&
                                    statement.Effect.toUpperCase() === 'DENY' &&
                                    s3BucketAssociations[bucketName][distributionId].includes(condition) &&  
                                    !restrictedOrigins.includes(condition)) {
                        restrictedOrigins.push(condition);
                    }

                    if (statement.Effect &&
                                statement.Effect.toUpperCase() === 'ALLOW' &&
                                s3BucketAssociations[bucketName][distributionId].includes(condition) &&   
                                !allowedOrigins.includes(condition)) {
                        allowedOrigins.push(condition);
                    }
                }
            }
            var policyFailures = [];
            var missingOrigins = s3BucketAssociations[bucketName][distributionId].filter(function(item) {
                return !allowedOrigins.includes(item) && !restrictedOrigins.includes(item);
            });

            restrictedOrigins = restrictedOrigins.concat(missingOrigins);

            if (unknownConditions.length) policyFailures.push(`allows access to these unknown sources: ${unknownConditions.join(', ')}`);
            if (restrictedOrigins.length) policyFailures.push(`does not allow access to these CloudFront origins: ${restrictedOrigins.join(', ')}`);

            if (policyFailures.length) {
                helpers.addResult(results, 2, `S3 bucket is origin to distribution "${distributionId}" and ${policyFailures}`, bucketLocation, `arn:aws:s3:::${bucketName}`);
            } else {
                helpers.addResult(results, 0,
                    `S3 bucket is origin to only one CloudFront distribution which is: ${distributionId}`, bucketLocation, `arn:aws:s3:::${bucketName}`);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};

function createAssociation(s3BucketAssociations,bucketName,distributionId,cfUser){
    if (s3BucketAssociations[bucketName]) {
        if (s3BucketAssociations[bucketName][distributionId]) s3BucketAssociations[bucketName][distributionId].push(cfUser);
        else {
            s3BucketAssociations[bucketName][distributionId] = [cfUser];
        }
    } else {
        s3BucketAssociations[bucketName] = {};
        s3BucketAssociations[bucketName][distributionId] = [cfUser];
        s3BucketAssociations[bucketName][distributionId].OACfound = false;
    }

}