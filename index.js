const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const sendgridMail = require('@sendgrid/mail');
const crypto = require('crypto');
const cors = require('cors'); 

const app = express();
const port = 3000;

app.use(cors()); 
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'anamnesia',
  port: 3306
});

db.connect((err) => {
  if (err) {
    console.error('Erro ao conectar ao MySQL:', err);
    process.exit(1);
  } else {
    console.log('Conexão com MySQL bem-sucedida!');
    createTable();
  }
});

function createTable() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(100) NOT NULL UNIQUE,
      senha VARCHAR(255) NOT NULL,
      nome_completo VARCHAR(255) NOT NULL,
      cidade VARCHAR(100) NOT NULL,
      data_nascimento DATE NOT NULL,
      codigo_verificacao VARCHAR(40) DEFAULT NULL,
      verificado BOOLEAN DEFAULT FALSE
    )
  `;
  db.query(createTableQuery, (err) => {
    if (err) {
      console.error('Erro ao criar a tabela:', err);
    } else {
      console.log('Tabela "usuarios" criada ou já existe.');
    }
  });
}

app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ mensagem: 'Erro no servidor!' });
    }

    if (result.length === 0 || !result[0].verificado) {
      return res.status(400).json({ mensagem: 'Usuário não encontrado ou não verificado!' });
    }

    bcrypt.compare(senha, result[0].senha, (err, isMatch) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ mensagem: 'Erro ao verificar a senha!' });
      }

      if (!isMatch) {
        return res.status(400).json({ mensagem: 'Senha incorreta!' });
      }

      res.status(200).json({ mensagem: 'Login bem-sucedido!' });
    });
  });
});

app.post('/enviar-codigo', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ mensagem: 'O email é obrigatório!' });
  }

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
    if (err) {
      console.error('Erro ao verificar o e-mail:', err);
      return res.status(500).json({ mensagem: 'Erro ao verificar o e-mail!' });
    }

    if (result.length > 0 && result[0].verificado === true) {
      return res.status(400).json({ mensagem: 'Email já registrado e verificado!' });
    }

    const codigo = crypto.randomInt(100000, 999999).toString();

    db.query('UPDATE usuarios SET codigo_verificacao = ?, verificado = false WHERE email = ?', [codigo, email], (err) => {
      if (err) {
        console.error('Erro ao atualizar o código:', err);
        return res.status(500).json({ mensagem: 'Erro ao atualizar o código!' });
      }

      const msg = {
        to: email,
        from: 'anamnesia.suporte@gmail.com',
        subject: 'Código de Verificação',
        text: `Seu código de verificação é: ${codigo}`,
        html: `<strong>Seu código de verificação é: ${codigo}</strong>`
      };

      sendgridMail
        .send(msg)
        .then(() => {
          console.log('Código de verificação enviado para o e-mail');
          res.status(200).json({ mensagem: 'Código de verificação enviado para o e-mail!' });
        })
        .catch((error) => {
          console.error(error);
          res.status(500).json({ mensagem: 'Erro ao enviar o e-mail!' });
        });
    });
  });
});


app.post('/verificar-codigo', (req, res) => {
  const { email, codigo } = req.body;

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
    if (err) {
      console.error('Erro ao verificar o código:', err);
      return res.status(500).json({ mensagem: 'Erro no servidor!' });
    }

    if (result.length === 0) {
      return res.status(400).json({ mensagem: 'Email não registrado!' });
    }

    if (result[0].codigo_verificacao !== codigo) {
      return res.status(400).json({ mensagem: 'Código inválido!' });
    }

    db.query('UPDATE usuarios SET verificado = true WHERE email = ?', [email], (err) => {
      if (err) {
        console.error('Erro ao atualizar o status de verificação:', err);
        return res.status(500).json({ mensagem: 'Erro ao verificar o código!' });
      }

      res.status(200).json({ mensagem: 'Usuário verificado com sucesso!' });
    });
  });
});


app.post('/registro', (req, res) => {
  const { email, senha, nome_completo, cidade, data_nascimento, codigo } = req.body;

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ mensagem: 'Erro no servidor!' });
    }

    if (result.length > 0) {
      if (!result[0].verificado) {
        const novoCodigo = crypto.randomInt(100000, 999999).toString();

        db.query('UPDATE usuarios SET codigo_verificacao = ?, verificado = false WHERE email = ?', [novoCodigo, email], (err) => {
          if (err) {
            console.error('Erro ao atualizar o código:', err);
            return res.status(500).json({ mensagem: 'Erro ao reenviar o código!' });
          }

          const msg = {
            to: email,
            from: 'anamnesia.suporte@gmail.com',
            subject: 'Código de Verificação',
            text: `Seu código de verificação é: ${novoCodigo}`,
            html: `<strong>Seu código de verificação é: ${novoCodigo}</strong>`
          };

          sendgridMail
            .send(msg)
            .then(() => {
              console.log('Novo código enviado para o e-mail');
              res.status(200).json({ mensagem: 'Novo código enviado para o e-mail!' });
            })
            .catch((error) => {
              console.error(error);
              res.status(500).json({ mensagem: 'Erro ao enviar o e-mail!' });
            });
        });

        return;
      }

      return res.status(400).json({ mensagem: 'Este e-mail já está registrado e verificado!' });
    }

    bcrypt.hash(senha, 10, (err, hash) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ mensagem: 'Erro ao criar a senha!' });
      }

      const query = 'INSERT INTO usuarios (email, senha, nome_completo, cidade, data_nascimento) VALUES (?, ?, ?, ?, ?)';
      db.query(query, [email, hash, nome_completo, cidade, data_nascimento], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ mensagem: 'Erro ao registrar usuário!' });
        }

        const codigo = crypto.randomInt(100000, 999999).toString();

        db.query('UPDATE usuarios SET codigo_verificacao = ? WHERE email = ?', [codigo, email], (err) => {
          if (err) {
            console.error('Erro ao gerar código de verificação:', err);
            return res.status(500).json({ mensagem: 'Erro ao gerar o código!' });
          }

          const msg = {
            to: email,
            from: 'anamnesia.suporte@gmail.com',
            subject: 'Código de Verificação',
            text: `Seu código de verificação é: ${codigo}`,
            html: `<strong>Seu código de verificação é: ${codigo}</strong>`
          };

          sendgridMail
            .send(msg)
            .then(() => {
              console.log('Código enviado para o e-mail');
              res.status(200).json({ mensagem: 'Código de verificação enviado para o e-mail!' });
            })
            .catch((error) => {
              console.error(error);
              res.status(500).json({ mensagem: 'Erro ao enviar o e-mail!' });
            });
        });
      });
    });
  });
});


app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
