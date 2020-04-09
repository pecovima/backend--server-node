var jwt = require('jsonwebtoken');

var SEDD = require('../config/config').SEED;



//=================================
//verificar token-middleware
//================================
exports.verificaToken = function(req, res, next) {

    var token = req.query.token;

    jwt.verify(token, SEDD, (err, decoded) => {

        if (err) {
            return res.status(401).json({
                ok: false,
                mensaje: 'Token incorrecto!',
                errors: err
            });
        }

        req.usuario = decoded.usuario;

        next();
        /* res.status(200).json({
             ok: true,
             decode: decode
         });*/

    });
}


//=================================
//verificar ADMIN
//================================
exports.verificaADMIN_ROLE = function(req, res, next) {


    var usuario = req.usuario;

    if (usuario.role === 'ADMIN_ROLE') {
        next();
        return;
    } else {

        return res.status(401).json({
            ok: false,
            mensaje: 'Token incorrecto-No es administrador!',
            errors: { message: 'No es administrador, no es permitido' }
        });

    }

}


//=================================
//verificar ADMIN o mismo usuario
//================================
exports.verificaADMIN_o_MISMOUSER = function(req, res, next) {


    var usuario = req.usuario;
    var id = req.params.id;

    if (usuario.role === 'ADMIN_ROLE' || usuario._id === id) {
        next();
        return;
    } else {

        return res.status(401).json({
            ok: false,
            mensaje: 'Token incorrecto-No es administrador ni es el mismo user!',
            errors: { message: 'No es administrador, no es permitido' }
        });

    }

}