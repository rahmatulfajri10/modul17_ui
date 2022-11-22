const jwt = require('jsonwebtoken');


const SECRET = process.env.SECRET
const Auth = {
    verifyToken(req, res, next){
      // const token = req.cookies['JWT'];
      const {token} =req.body
        console.log(token);
        if (token) {
          // 12. Lalukan jwt verify 
          try {
            const decoded = jwt.verify(token, SECRET);
            req.data = decoded;
          } catch (err) {
            return res.status(401).send("Invalid Token");
          }
          return next();
        } else {
          res.status(403).send({message: 'Youre not authenticated, please login first'})
            console.log('Youre not authenticated');
        }
    
  }
}

module.exports = Auth;