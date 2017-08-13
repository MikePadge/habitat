import { expect } from 'chai';
import supertest = require('supertest');

const request = supertest('http://localhost:9636/v1');
const globalAny:any = global;


describe('Package related API', function() {
  describe('Upload a package', function() {
    it('sends the package to the depot', function(done) {
      // convert the base64 encoded hart file back into binary data for upload
      let p = window.atob(pkgToUpload);

      request.post('/depot/pkgs/core/linux-headers/4.3/20170513200956')
        .set('Authorization', globalAny.bobo_bearer)
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .query({checksum: '8f5d28dbe6e77d01f859eba9300df981f758312724f5d25925f1f22c0cc8ff77'})
        .send("HAHA THIS IS AWESOME")
        .serialize(function(data) {
            return data;
        })
        .expect(201)
        .end(function(err, res) {
          console.log('BODY');
          console.log(res.text);
          console.log('ERR');
          console.log(err);
          console.log('RES');
          console.log(res);
          done(err);
        });
    });
  });

  describe('Promote a package', function() {
    it('makes the package appear in the specified channel', function(done) {
      request.post('/depot/channels/core/foo/pkgs/linux-headers/4.3/20170513200956/promote')
        .set('Authorization', globalAny.bobo_bearer)
        .expect(200)
        .end(function(err, res) {
            done(err);
        });
    });
  });
});