#include "Message.hpp"
#include <json/json.hpp>

auto main() -> int{
    try{
    std::string Secret, Public, Receiver, Msg;
    std::cout << "Write your secret key (Write 'None' if you haven't): ";
    std::cin >> Secret;
    std::unique_ptr<sEC> key;
    if(Secret!="None"){
        std::cout << "Write your public key: ";
        std::cin >> Public;
        key = std::make_unique<sEC>(Secret,Public);
    }else{
        key = std::make_unique<sEC>();
        std::cout << *key << std::endl;
    }
    std::cout << "Write Receiver public key: ";
    std::cin >> Receiver;

    std::unique_ptr<pEC> receiver = std::make_unique<pEC>(Receiver);
    
    std::cout << "Write MSG: ";
    std::cin >> Msg;
    Msg.resize(((Msg.size()+15)/16)*16);
    std::vector<unsigned char> information(Msg.begin(),Msg.end());

    const auto iv = GenerateIV();
    const auto aesKEY = key->Exchange(*receiver);
    auto data = aes256_cbc_enc(information,aesKEY,iv);

    Message msg{key->GetKey(),*receiver,data,iv,std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())};

    auto sig = key->Sign(msg.GetHash());
    msg.signature = sig;

    if(msg.Verify()){
        std::cout << "VALID\n";
    }

    nlohmann::json response;
    response["sender"] = key->GetPkey();
    response["receiver"] = receiver->GetPkey();
    response["data"] = data;
    response["iv"] = iv;
    response["timestamp"] = msg.timestamp;
    response["signature"] = sig;

    std::string result = response.dump();
    std::cout << result << std::endl;

    std::vector<unsigned char> NewData = response["data"];

    std::vector<unsigned char> decrypted{};
    decrypted = aes256_cbc_dec(data,aesKEY,iv);
    std::string MyRes(decrypted.begin(),decrypted.end());
    std::cout << MyRes << std::endl;

    }
    catch(std::exception& ex){
        std::cerr << ex.what() << std::endl;
    }
    return 0;
}