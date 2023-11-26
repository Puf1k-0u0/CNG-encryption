#pragma once
#include "../cng_interface.h"

bool init(BCRYPT*);
void Cleanup(BCRYPT);
bool destroy_key(BCRYPT);
bool clear_crypt_data(BCRYPT);
