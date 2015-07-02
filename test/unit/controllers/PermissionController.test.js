var assert = require('assert');
var request = require('supertest');

var adminAuth = {
  Authorization: 'Basic YWRtaW5AZXhhbXBsZS5jb206YWRtaW4xMjM0'
};

describe('PermissionController', function () {

  var agent
  before(function(done) {

    agent = request.agent(sails.hooks.http.app);

    agent
      .post('/user')
      .set('Authorization', adminAuth.Authorization)
      .send({
        username: 'newuser1',
        email: 'newuser1@example.com',
        password: 'lalalal1234'
      })
      .expect(200, function (err) {

        if (err)
          return done(err);

        agent
          .post("/permission")
          .set('Authorization', adminAuth.Authorization)
          .send({
            model: 2,
            criteria: {
              where: {
                id: 1
              }
            },
            action: "delete",
            relation: "user",
            user: 2
          })
          .expect(201, function (err) {
            if (err)
              return done(err);

            agent
              .post("/permission")
              .set('Authorization', adminAuth.Authorization)
              .send({
                model: 2,
                object: 21,
                action: "read",
                relation: "user",
                user: 2,
                deny: true
              })
              .expect(201, function (err) {
                  if (err)
                    return done(err);

                  agent
                    .post("/permission")
                    .set('Authorization', adminAuth.Authorization)
                    .send({
                      model: 2,
                      object: 20,
                      action: "read",
                      relation: "role",
                      role: 2,
                      deny: true
                    })
                    .expect(201, function (err) {
                      if (err)
                        return done(err);

                        agent
                          .post("/permission")
                          .set('Authorization', adminAuth.Authorization)
                          .send({
                            model: 2,
                            object: 19,
                            action: "read",
                            relation: "role",
                            role: 2,
                            deny: true
                          })
                          .expect(201, function (err) {
                            if (err)
                              return done(err);

                              agent
                                .post("/permission")
                                .set('Authorization', adminAuth.Authorization)
                                .send({
                                  model: 2,
                                  object: 19,
                                  action: "read",
                                  relation: "user",
                                  user: 2
                                })
                                .expect(201, function (err) {
                                  if (err)
                                    return done(err);

                                  agent
                                    .post('/auth/local')
                                    .send({
                                      identifier: 'newuser1',
                                      password: 'lalalal1234'
                                    })
                                    .expect(200)
                                    .end(function (err, res) {
                                      agent.saveCookies(res);
                                      return done(err);
                                    });
                                });
                          });
                      });
                    });
              });
          });

      });

  describe('Permission Controller', function () {

    describe('User with Registered Role', function () {

      describe('#find()', function () {

        it('should be able to read permissions', function (done) {

          agent
            .get('/permission')
            .expect(200)
            .end(function (err, res) {

              var permissions = res.body;

              assert.ifError(permissions.error);
              done(err || permissions.error);

            });

        });

        it('should be able to read permissions but should not contain permissions 20,21', function (done) {

          agent
            .get('/permission')
            .expect(200)
            .end(function (err, res) {

              var permissions = res.body;

              var contains = false;
              permissions.forEach(function (object) {
                if (object.id == 21 || object.id == 20) {
                  contains = true;
                }
              });

              assert.equal(contains, false);
              assert.ifError(permissions.error);
              done(err || permissions.error);

            });

        });

        it('should be able to read permissions and should contain permission 19', function (done) {

          agent
              .get('/permission')
              .expect(200)
              .end(function (err, res) {

                var permissions = res.body;

                var contains = false;
                permissions.forEach(function (object) {
                  if (object.id == 19) {
                    contains = true;
                  }
                });

                assert.equal(contains, true);
                assert.ifError(permissions.error);
                done(err || permissions.error);

              });

        });

      });

      describe('#find(21)', function () {

        it('should not be able to read permission 21 (user level deny permission)', function (done) {

          agent
            .get('/permission/21')
            .expect(400)
            .end(function (err, res) {

                assert(_.isString(res.body.error));
                done(err);

            });

        });

      });

      describe('#find(20)', function () {

        it('should not be able to read permission 20 (role level deny permission)', function (done) {

          agent
            .get('/permission/20')
            .expect(400)
            .end(function (err, res) {

                assert(_.isString(res.body.error));
                done(err);

            });

        });

      });

      describe('#find(19)', function () {

        it('should be able to read permission 19 (role level deny permission and user level granted permission)', function (done) {

          agent
            .get('/permission/19')
            .expect(200)
            .end(function (err, res) {
              var permissions = res.body;
              assert.ifError(permissions.error);
              done(err || permissions.error);

            });

        });

      });

    });

    describe('User with Registered Role and granted to delete Permission 1', function () {
      describe("#delete()", function () {
        it('should be able to delete permission 1', function (done) {
          agent
            .delete("/permission/1")
            .expect(200)
            .end(function (err, res) {
                var permissions = res.body;

                assert.ifError(permissions.error);
                done(err || permissions.error);
            });
        });
      });
    });

  });


});
