const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001; // Porta para o backend

// Middlewares
app.use(cors()); // Permite requisições de diferentes origens (ex: seu frontend)
app.use(express.json()); // Para interpretar o corpo da requisição como JSON

// --- Configuração da API MozPayment ---
const MOZPAYMENT_API_URL = 'https://mozpayment.co.mz/api/1.1/wf/pagamentorotativompesa';
const CARTEIRA_ID = '1746519798335x143095610732969980'; // ID da sua carteira
const VALOR_FIXO = '1'; // Preço fixo de 1 MT, conforme solicitado

// --- Endpoint para o Frontend Chamar ---
app.post('/api/efetuar-pagamento', async (req, res) => {
    // Extrai os dados enviados pelo frontend
    const { numero, quemComprou } = req.body;

    // Validação básica dos dados de entrada
    if (!numero || !quemComprou) {
        return res.status(400).json({ message: 'Número do telefone e nome do comprador são obrigatórios.' });
    }

    // Monta o corpo (payload) da requisição para a API MozPayment
    // com base na interpretação das mensagens de erro da API e padrões comuns.
    const payloadParaMozPayment = {
        carteira: CARTEIRA_ID,
        numero: numero,             // Chave "numero" (sem acento), conforme indicado por erros anteriores da API
        "quem comprou": quemComprou,  // Chave "quem comprou" (com espaço), conforme sua especificação original
        valor: VALOR_FIXO
    };

    console.log(`[${new Date().toISOString()}] Enviando para MozPayment:`, JSON.stringify(payloadParaMozPayment, null, 2));

    try {
        // Faz a requisição POST para a API da MozPayment
        // !!! ATENÇÃO: VERIFIQUE SE A API MOZPAYMENT REQUER CABEÇALHOS DE AUTENTICAÇÃO !!!
        // Se for necessário um token ou API key, ele deve ser adicionado aqui nos headers.
        // Exemplo hipotético:
        // const headersApi = {
        //     'Content-Type': 'application/json',
        //     'Authorization': 'Bearer SEU_TOKEN_AQUI' // ou 'X-Api-Key': 'SUA_CHAVE_AQUI'
        // };
        // const apiResponse = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, { headers: headersApi });

        const apiResponse = await axios.post(MOZPAYMENT_API_URL, payloadParaMozPayment, {
            headers: {
                'Content-Type': 'application/json'
                // Adicione aqui quaisquer outros cabeçalhos necessários (ex: autenticação)
            }
        });

        // Log da resposta da MozPayment
        console.log(`[${new Date().toISOString()}] Resposta da MozPayment - Status: ${apiResponse.status}, Corpo:`, JSON.stringify(apiResponse.data, null, 2));

        // --- Tratamento das Respostas da MozPayment (conforme sua documentação) ---
        // A API MozPayment parece usar o status HTTP para indicar o resultado diretamente.
        if (apiResponse.status === 200) {
            // 200 = Pagamento Realizado com Sucesso
            return res.status(200).json({
                message: 'Pagamento Realizado com Sucesso!',
                data: apiResponse.data
            });
        } else if (apiResponse.status === 201) {
            // 201 = Erro na Transação (segundo sua documentação)
            // Nota: Normalmente, 201 significa "Created" (sucesso). É incomum ser um erro.
            return res.status(201).json({ // Retornando 201 para o frontend, conforme a lógica da API
                message: 'Erro na Transação (API MozPayment retornou 201).',
                errorDetails: apiResponse.data
            });
        } else {
            // Outros status de sucesso inesperados da MozPayment
            return res.status(apiResponse.status).json({
                message: `Resposta inesperada da API de pagamento (Status: ${apiResponse.status})`,
                data: apiResponse.data
            });
        }

    } catch (error) {
        // --- Tratamento de Erros na Chamada à API MozPayment ---
        let statusDoErroParaFrontend = 500; // Padrão para erro interno
        let corpoDoErroParaFrontend = { message: 'Erro interno ao processar o pagamento.' };

        if (error.response) {
            // A requisição foi feita e a API da MozPayment respondeu com um status de erro (4xx ou 5xx)
            const statusCodeDaApi = error.response.status;
            const errorDataDaApi = error.response.data;

            console.error(`[${new Date().toISOString()}] Erro ao chamar a API MozPayment - Status Real da API: ${statusCodeDaApi}, Corpo da Resposta da API:`, JSON.stringify(errorDataDaApi, null, 2));

            statusDoErroParaFrontend = statusCodeDaApi; // Repassa o status da API MozPayment

            // Mapeia os códigos de erro da MozPayment para mensagens
            switch (statusCodeDaApi) {
                case 400: // PIN Errado ou Dados Inválidos (incluindo "DADOS_AUSENTES")
                    corpoDoErroParaFrontend = {
                        message: errorDataDaApi && errorDataDaApi.message ? errorDataDaApi.message : 'PIN Errado ou dados inválidos fornecidos à MozPayment.',
                        errorDetails: errorDataDaApi
                    };
                    break;
                case 403: // Proibido (Forbidden) - pode ser autenticação, IP, etc.
                    corpoDoErroParaFrontend = {
                        message: errorDataDaApi && errorDataDaApi.message ? errorDataDaApi.message : 'Acesso proibido à API de pagamento. Verifique as permissões ou autenticação.',
                        errorDetails: errorDataDaApi
                    };
                    break;
                case 422: // Saldo Insuficiente
                    corpoDoErroParaFrontend = {
                        message: errorDataDaApi && errorDataDaApi.message ? errorDataDaApi.message : 'Saldo Insuficiente.',
                        errorDetails: errorDataDaApi
                    };
                    break;
                default:
                    corpoDoErroParaFrontend = {
                        message: errorDataDaApi && errorDataDaApi.message ? errorDataDaApi.message : `Erro na API de Pagamento (Status: ${statusCodeDaApi}).`,
                        errorDetails: errorDataDaApi
                    };
            }
        } else if (error.request) {
            // A requisição foi feita mas nenhuma resposta foi recebida
            console.error(`[${new Date().toISOString()}] Erro ao chamar a API MozPayment: Nenhuma resposta recebida.`, error.request);
            corpoDoErroParaFrontend = { message: 'Nenhuma resposta recebida da API de pagamento. Verifique a conexão ou o endpoint.' };
        } else {
            // Algo aconteceu ao configurar a requisição que acionou um erro
            console.error(`[${new Date().toISOString()}] Erro ao configurar a requisição para MozPayment:`, error.message);
            corpoDoErroParaFrontend = { message: `Erro ao configurar a requisição: ${error.message}` };
        }

        return res.status(statusDoErroParaFrontend).json(corpoDoErroParaFrontend);
    }
});

// --- Inicia o Servidor Backend ---
app.listen(PORT, () => {
    console.log(`Servidor backend rodando na porta ${PORT} em ${new Date().toLocaleString()}`);
    console.log(`Aguardando requisições do frontend em http://localhost:${PORT}/api/efetuar-pagamento`);
});
