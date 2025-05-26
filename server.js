const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const CARTEIRA_ID = '1746519798335x143095610732969980';

app.post('/api/payment', async (req, res) => {
  const { numero, valor, quemComprou } = req.body;

  if (!numero || !valor || !quemComprou) {
    return res.status(400).json({ error: 'Faltando parâmetros obrigatórios.' });
  }

  try {
    // Monta o payload para a API MozPayment
    const payload = {
      carteira: CARTEIRA_ID,
      numero: numero,
      "quem comprou": quemComprou,
      valor: valor
    };

    const response = await axios.post(
      'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativoemola',
      payload
    );

    // Verifica resposta
    if (response.data.success === 'yes') {
      // Monta link WhatsApp para enviar ao cliente
      const message = encodeURIComponent(
        `Olá ${quemComprou}, seu pagamento de ${valor}MT foi aprovado! Acesse seu link: https://seulink.aqui`
      );
      const whatsappLink = `https://wa.me/258${numero}?text=${message}`;

      return res.json({ success: true, whatsappLink });
    } else {
      return res.status(400).json({ success: false, message: 'Pagamento reprovado' });
    }
  } catch (err) {
    console.error(err.message);
    return res.status(500).json({ error: 'Erro ao processar o pagamento.' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server rodando na porta ${PORT}`));
