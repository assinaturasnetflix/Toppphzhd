const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Middlewares
app.use(cors());
app.use(express.json());

const MOZPAYMENT_API_URL = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativompesa';
const CARTEIRA_ID = '1746519798335x143095610732969980';
const VALOR_FIXO = '1';

app.post('/api/efetuar-pagamento', async (req, res) => {
    const { numero, quemComprou } = req.body; // quemComprou vem do frontend

    if (!numero || !quemComprou) {
        return res.status(400).json({ message: 'Número e nome do comprador são obrigatórios.' });
    }

    const payloadParaMozPayment = {
        carteira: CARTEIRA_ID,
        "número": numero,             // Mantendo "número" com acento, como no seu teste anterior bem-sucedido para o erro de DADOS_AUSENTES
        "quem comprou": quemComprou,  // CORRIGIDO: Deve ser "quem comprou"
        valor: VALOR_FIXO
    };

    console.log('Enviando para MozPayment:', JSON.stringify(payloadParaMozPayment, null, 2));

    try {
        // !!! VERIFIQUE SE A API MOZPAYMENT REQUER CABEÇALHOS DE AUTENTICAÇÃO !!!
        // Exemplo:
        // const headers = {
        //     'Content-Type': 'application/json',
        //     'Authorization': 'Bearer SEU_TOKEN_AQUI' // ou 'X-Api-Key': 'SUA_CHAVE_AQUI'
        // };
        // const response = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, { headers });

        const response = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, {
            headers: {
                'Content-Type': 'application/json'
                // Adicione aqui quaisquer outros cabeçalhos de autenticação necessários
            }
        });

        console.log('Resposta da MozPayment:', response.status, response.data);

        if (response.status === 200) {
            return res.status(200).json({ message: 'Pagamento Realizado com Sucesso', data: response.data });
        } else if (response.status === 201) {
             return res.status(201).json({ message: 'Erro na Transação (API retornou 201)', errorDetails: response.data });
        } else {
            return res.status(response.status).json({ message: 'Resposta inesperada da API de pagamento', data: response.data });
        }

    } catch (error) {
        const errorResponseData = error.response ? error.response.data : { message: error.message, "código de status": 500 };
        const actualStatusCodeFromMozPayment = error.response ? error.response.status : 500;

        // Log para depuração no console do backend
        console.error(`Erro ao chamar a API MozPayment. Status Real: ${actualStatusCodeFromMozPayment}, Corpo da Resposta da API: ${JSON.stringify(errorResponseData, null, 2)}`);

        let messageToFrontend = `Erro ao processar pagamento. Tente novamente.`;
        if (typeof errorResponseData === 'object' && errorResponseData !== null && errorResponseData.message) {
            messageToFrontend = errorResponseData.message; // Usa a mensagem da API MozPayment se disponível
        } else if (typeof errorResponseData === 'string') {
            messageToFrontend = errorResponseData;
        }

        // Retorna o status code que recebemos da MozPayment (ex: 403) para o frontend
        return res.status(actualStatusCodeFromMozPayment).json({
            message: messageToFrontend,
            errorDetails: errorResponseData,
            mozPaymentStatus: actualStatusCodeFromMozPayment // Adiciona o status real para clareza
        });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT} em ${new Date().toString()}`);
});
