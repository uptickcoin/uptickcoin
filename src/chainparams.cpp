// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <consensus/consensus.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>
#include "arith_uint256.h"

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Bitcoin Seesaws Above and Below 23K Again";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.nSubsidyHalvingInterval = 700000;
        consensus.BIP16Exception = uint256S("0x0000093c8955d637f8fd0c0286111069fcc88cc7bb025d1b22141ed7ed358a2e");
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x000003ccec76446ce027bfb0f151510a1100e07afc3426babefb04a23195518c");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 3 * 60;
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nLastPOWBlock = 10000;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock + 
                                    consensus.nMPoSRewardRecipients + 
                                    COINBASE_MATURITY;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00"); //block 101

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000516259f416d0b6508a796b862de20759f55ec922423bbb7f022aa9ae3c"); //block 101

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x55; // U
        pchMessageStart[1] = 0x50; // P
        pchMessageStart[2] = 0x54; // T
        pchMessageStart[3] = 0x43; // C
        nDefaultPort = 2090;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 2;
        m_assumed_chain_state_size = 1;
                
    
        genesis = CreateGenesisBlock(1674617040, 398151, 0x1e0fffff, 1, 50 * COIN);                  

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000093c8955d637f8fd0c0286111069fcc88cc7bb025d1b22141ed7ed358a2e"));
        assert(genesis.hashMerkleRoot == uint256S("0x5579dfc4f5cda55efe16d48b5a231cb4240a16bb58098c35b3be27c7fd48f2c0"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        
        vSeeds.emplace_back("139.144.254.185");
        vSeeds.emplace_back("139.144.148.169");
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68); // address starts with S, P2PKH
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,130); // address starts with s, P2SH
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,149);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x09, 0x61, 0xA3, 0xB2};
        base58Prefixes[EXT_SECRET_KEY] = {0x09, 0x61, 0xD4, 0xF1};

        bech32_hrp = "utc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 0, uint256S("0x0000093c8955d637f8fd0c0286111069fcc88cc7bb025d1b22141ed7ed358a2e")},
                //{ 1, uint256S("0x")},

            }

        };

        chainTxData = ChainTxData{
            // Data from RPC:  getchaintxstats 101 000000516259f416d0b6508a796b862de20759f55ec922423bbb7f022aa9ae3c
            /* nTime    */ 1674617040,
            /* nTxCount */ 102,
            /* dTxRate  */ 0.05089058524173028,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.nSubsidyHalvingInterval = 700000;
        consensus.BIP16Exception = uint256S("0x0000046619a3ade01c0b2b5ed85de8babbddf0dc4372342b8b8c4282d75602f7");
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = consensus.SegwitHeight + consensus.nMinerConfirmationWindow;     
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 3 * 60; // every 10 blocks
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nLastPOWBlock = 501;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock + 
                                    consensus.nMPoSRewardRecipients + 
                                    COINBASE_MATURITY;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000007d54e2cf994457b30929435b81705951f0d6aae447d67beb6e269900e7b"); // Genesis

        pchMessageStart[0] = 0x75; // u
        pchMessageStart[1] = 0x74; // t
        pchMessageStart[2] = 0x63; // c
        pchMessageStart[3] = 0x74; // t
        nDefaultPort = 12191;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        
        genesis = CreateGenesisBlock(1674620640, 633636, 0x1e0fffff, 1, 50 * COIN);       

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000007d54e2cf994457b30929435b81705951f0d6aae447d67beb6e269900e7b"));
        assert(genesis.hashMerkleRoot == uint256S("0x5579dfc4f5cda55efe16d48b5a231cb4240a16bb58098c35b3be27c7fd48f2c0"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,127);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,130);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tutc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0x000007d54e2cf994457b30929435b81705951f0d6aae447d67beb6e269900e7b")},
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000b7ab6ce61eb6d571003fbe5fe892da4c9b740c49a07542462d
            /* nTime    */ 1661424960,
            /* nTxCount */ 1,
            /* dTxRate  */ 0.1,
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;      
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 10 * 3 * 60; // every 10 blocks
        consensus.nPowTargetSpacing = 1 * 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = 5000;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = COINBASE_MATURITY;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x72; // r
        pchMessageStart[1] = 0x65; // e
        pchMessageStart[2] = 0x67; // g
        pchMessageStart[3] = 0x74; // t
        nDefaultPort = 22292;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        genesis = CreateGenesisBlock(1674624240, 456089, 0x1e0fffff, 1, 50 * COIN);  

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000000a9523af9d82dc2954b446610f0f755d467bc10604b8f95a0295cb71654"));
        assert(genesis.hashMerkleRoot == uint256S("0x5579dfc4f5cda55efe16d48b5a231cb4240a16bb58098c35b3be27c7fd48f2c0"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("0x000000a9523af9d82dc2954b446610f0f755d467bc10604b8f95a0295cb71654")},
            }
        };

        chainTxData = ChainTxData{
            1674624240,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,122);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,130);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rcros";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (gArgs.IsArgSet("-segwitheight")) {
        int64_t height = gArgs.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
