#include "easyssl.hpp"


namespace easyssl {


    //auto library initialization
    static struct init {
        init() {
            if (!EASYSSL_init()) {
                throw error(*EASYSSL_get_last_error());
            }
        }
        ~init() {
            EASYSSL_cleanup();
        }
    } init;


} //namespace easyssl
