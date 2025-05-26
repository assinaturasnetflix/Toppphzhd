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
const VALOR_FIXO = '1'; // Preço fixo de 1 MT

app.post('/api/efetuar-pagamento', async (req, res) => {
    const { numero, quemComprou } = req.body;

    if (!numero || !quemComprou) {
        return res.status(400).json({ message: 'Número e nome do comprador são obrigatórios.' });
    }

    // Montando o corpo da requisição com os parâmetros no nível raiz do JSON
    const payloadParaMozPayment = {
        carteira: CARTEIRA_ID,
        numero: numero, // Se a API esperar "número" com acento, ajuste aqui. Por padrão, chaves JSON não usam acentos.
        "quem comprou": quemComprou, // Mantendo a chave com espaço, conforme o original
        valor: VALOR_FIXO
    };

    // No seu log, os campos "parâmetro" e "número" aparecem com acentos.
    // Se a API da MozPayment REALMENTE espera esses acentos NAS CHAVES JSON,
    // você teria que fazer:
    // const payloadParaMozPayment = {
    //     "carteira": CARTEIRA_ID,
    //     "número": numero, // <--- Chave com acento, se necessário
    //     "quem comprou": quemComprou,
    //     "valor": VALOR_FIXO
    // };
    // No entanto, é mais comum que as chaves JSON sejam em inglês e sem caracteres especiais/acentos.
    // Vou manter "numero" sem acento por enquanto, pois é mais padrão.
    // A chave "quem comprou" já está com espaço conforme a sua especificação original.

    console.log('Enviando para MozPayment (estrutura plana):', JSON.stringify(payloadParaMozPayment, null, 2));

    try {
        const response = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, {
            headers: {
                'Content-Type': 'application/json'
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
        // Formatando a saída do erro para corresponder ao formato do seu log
        const errorResponse = {
            "código de status": error.response ? error.response.status : 500,
            "corpo": error.response ? error.response.data : { message: error.message }
        };
        console.error('Erro ao chamar a API MozPayment:', JSON.stringify(errorResponse, null, 2));


        if (error.response) {
            const statusCode = error.response.status;
            let message = 'Erro desconhecido na transação.';
            const errorData = error.response.data;

            if (errorData && errorData.message) { // Usar a mensagem da API se disponível
                message = errorData.message;
            } else if (statusCode === 400) {
                message = 'PIN Errado ou dados inválidos fornecidos à MozPayment (verifique se todos os campos estão corretos e no formato esperado pela API).';
            } else if (statusCode === 422) {
                message = 'Saldo Insuficiente.';
            } else if (statusCode === 201) {
                 message = 'Erro na Transação (API retornou 201 e foi tratado como erro).';
            } else {
                 message = `Erro na API de Pagamento: Status ${statusCode}`;
            }
            return res.status(statusCode).json({ message: message, errorDetails: errorData });
        } else if (error.request) {
            return res.status(500).json({ message: 'Nenhuma resposta da API de pagamento.' });
        } else {
            return res.status(500).json({ message: 'Erro interno ao processar o pagamento.' });
        }
    }
});

app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT} em ${new Date().toString()}`);
});
