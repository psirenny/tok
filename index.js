var _ = require('underscore')
  , crypto = require('crypto')
  , moment = require('moment');

module.exports = function (options) {
  options = options || {};

  _.defaults(options, {
      expiration: 3600000
    , hashAlgorithm: 'sha1'
    , mode: 'hash'
  });

  if (!options.secretKey) {
    throw 'must provide a secretKey';
  }

  if (options.mode === 'store') {
    if (!options.load) throw 'must provide a load() function';
    if (!options.save) throw 'must provide a save() function';
  }

  var getHash = function (id, date) {
    id = _.isArray(id) ? id : [id];
    id = _.chain(id).push(date).join('').value();
    return crypto.createHmac(options.hashAlgorithm, options.secretKey).update(id).digest('hex');
  };

  return {
    check: function (id, token, callback) {
      var isExpired = function (token) {
        if (!options.expiration) return false;
        var elapsed = moment().diff(parseInt(token.date, 10));
        return elapsed > options.expiration;
      };

      switch (options.mode) {
        case 'hash':
          if (isExpired(token)) return callback('token expired');
          callback(token.hash === getHash(id, token.date) ? null : 'token invalid');
          break;
        case 'store':
          if (arguments.length < 3) {
            callback = token;
            token = null;
          }

          options.load(id, function (err, dbToken) {
            if (err) return callback(err);
            if (!dbToken) return callback('token invalid');
            if (isExpired(dbToken)) return callback('token expired');
            if (token) return callback(token.hash === dbToken.hash ? null : 'token invalid');
            callback(dbToken.hash === getHash(id, dbToken.date) ? null : 'token invalid');
          });

          break;
      }
    }
    , create: function (id, callback) {
      var date = +new Date()
        , hash = getHash(id, date)
        , token = {hash: hash, date: date};

      if (options.mode === 'hash') {
        return callback(null, token);
      }

      options.save(id, token, function (err) {
        callback(err, token);
      });
    }
  };
}