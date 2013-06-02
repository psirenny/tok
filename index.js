var _ = require('underscore')
  , crypto = require('crypto')
  , moment = require('moment');

module.exports = function (options) {
  _.defaults(options, {
      expiration: 3600000
    , hashAlgorithm: 'sha1'
    , method: 'hash'
  });

  if (!options.secretKey) {
    throw 'must provide a secretKey';
  }

  if (options.method !== 'hash') {
    if (!options.load) throw 'must provide a load() function';
    if (!options.save) throw 'must provide a save() function';
  }

  var getHash = function (id, value, date) {
    value = value || [];
    if (!_.isArray(id)) id = _.isObject(id) ? _.values(id) : [id];
    if (!_.isArray(value)) value = _.isObject(value) ? _.values(value) : [value];
    var str = _.chain(id).concat(value).push(date).join('').value();
    return crypto.createHmac(options.hashAlgorithm, options.secretKey).update(str).digest('hex');
  };

  return {
    check: function (id, token, callback) {
      var isExpired = function (token) {
        if (!options.expiration) return false;
        var elapsed = moment().diff(parseInt(token.date, 10));
        return elapsed > options.expiration;
      };

      if (options.method === 'hash') {
        if (isExpired(token)) return callback('token expired');
        return callback(token.hash === getHash(id, token.value, token.date) ? null : 'token invalid');
      }

      if (arguments.length < 3) {
        callback = token;
        token = null;
      }

      options.load(id, function (err, dbToken) {
        if (err) return callback(err);
        if (!dbToken) return callback('token not found');
        if (isExpired(dbToken)) return callback('token expired');
        if (token.hash) return callback(dbToken.hash === token.hash ? null : 'token invalid');
        return callback(dbToken.hash === getHash(id, token.value, token.date) ? null : 'token invalid');
      });
    }
    , create: function (id, value, callback) {
      var date = +new Date()
        , hash = getHash(id, value, date)
        , token = {date: date, hash: hash}
        , dbToken = {date: date, hash: hash}

      if (value) token.value = value;

      if (options.method === 'hash') {
        return callback(null, token);
      }

      options.save(id, dbToken, function (err) {
        if (value) delete token.hash;
        callback(err, token);
      });
    }
  };
}