#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define TAMANIO_INICIAL 101
#define REDIMENSION 1000

typedef enum estados {
    VACIO,
    BORRADO,
    OCUPADO
}estado_t;

typedef struct nodo{
    char* clave;
    void* dato;
    estado_t estado;
} nodo_t;


struct hash {
    nodo_t* tabla;
    size_t tam;
    size_t cant;
    hash_destruir_dato_t destruir_dato;
};

hash_t *hash_crear(hash_destruir_dato_t destruir_dato) {
    hash_t* hash = malloc(sizeof(hash_t));
    if (hash == NULL) return NULL;
    hash->tam = TAMANIO_INICIAL;
    hash->tabla = malloc(sizeof(nodo_t) * hash->tam);
    if(!hash->tabla){
        free(hash);
        return NULL;
    }
    for (size_t i = 0; i < hash->tam; i++){
        hash->tabla[i].clave = '\0';
        hash->tabla[i].dato = NULL;
        hash->tabla[i].estado = 0;
    }
    hash->cant = 0;
    hash->destruir_dato = destruir_dato;
    
    return hash;
}

size_t codigo_hash(const char* cp, size_t len)
{
    size_t hash = 0x811c9dc5;
    while (*cp) {
        hash ^= (unsigned char) *cp++;
        hash *= 0x01000193;
    }
    return (hash % len);
}

size_t hash_cantidad(const hash_t *hash) {
    return hash->cant;
}

void hash_destruir(hash_t *hash) {
    for (size_t i = 0; i < hash->tam; i ++) {
        if(hash->tabla[i].estado == OCUPADO){
            if(hash->destruir_dato){
                hash->destruir_dato(hash->tabla[i].dato);}          
            free(hash->tabla[i].clave);
        }
    }
    free(hash->tabla);
    free(hash);
}

void *hash_obtener(const hash_t *hash, const char *clave){
    size_t i = codigo_hash(clave, hash->tam);
    while(i != hash->tam){
        if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
            return hash->tabla[i].dato;
        }else if (hash->tabla[i].estado == VACIO){
            return NULL;
        }
        i ++;
    }
    if(i == hash->tam){ 
        i = 0;
        while(i != hash->tam){
            if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
                return hash->tabla[i].dato;
            }
            i ++;
        }
    }
    return NULL;
}

bool hash_pertenece(const hash_t *hash, const char *clave) {
    for (size_t i = codigo_hash(clave, hash->tam); i < hash->tam; i++) {
        if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
            return true;
        }
        else if (((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) != 0)) ||
         (hash->tabla[i].estado == BORRADO)) {
            continue;
        }
    }
    return false;
}

bool hay_redimension(hash_t* hash) {
    return hash->tam * 2/3 <= hash->cant ? true : false;
}

bool hash_redimensionar(hash_t* hash, size_t nuevo_tamanio){
    nodo_t* nueva_tabla = malloc(sizeof(nodo_t) * nuevo_tamanio);
    if (!nueva_tabla) return false;
    hash->cant = 0;
    for (size_t i = 0; i < nuevo_tamanio; i++){
        nueva_tabla[i].clave = '\0';
        nueva_tabla[i].dato = NULL;
        nueva_tabla[i].estado = 0;
    }
    for (size_t i = 0; i < hash->tam; i++){
        if(hash->tabla[i].estado == OCUPADO){
            size_t posicion = codigo_hash(hash->tabla[i].clave, nuevo_tamanio);
            if(nueva_tabla[posicion].estado == OCUPADO){
                while(nueva_tabla[posicion].estado == OCUPADO){
                    posicion ++;
                    if(posicion == nuevo_tamanio) posicion = 0;
                }
            }
            nueva_tabla[posicion] = hash->tabla[i];
            hash->cant ++;
        } 
    }
    
    free(hash->tabla);
    hash->tabla = nueva_tabla;
    hash->tam = nuevo_tamanio;
    return true; 
}


bool hash_guardar(hash_t *hash, const char *clave, void *dato) {
    if(hay_redimension(hash)){
        if(!hash_redimensionar(hash, hash->tam * 100)){
            return false;
        }
    }
    for (size_t i = codigo_hash(clave, hash->tam); i < hash->tam; i++) {
        if(i == hash->tam && (hash->tabla[i].estado != VACIO)){
            i = 0;}
        if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
            if(hash->destruir_dato){
                hash->destruir_dato(hash->tabla[i].dato);
            }
            hash->tabla[i].dato = dato;
            break;
        } 
        else if (((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) != 0)) ||
        (hash->tabla[i].estado == BORRADO)){
            continue;
        }
        else if (hash->tabla[i].estado == VACIO) {
            //char* copiar_clave = calloc(sizeof(char), strlen(clave)+1 );
            //if(!copiar_clave) return false;
            hash->tabla[i].clave = strdup(clave);
            hash->tabla[i].dato = dato;
            hash->tabla[i].estado = OCUPADO;
            hash->cant ++;
            break;
        }

    }
    return true;
}

void *hash_borrar(hash_t *hash, const char *clave){
    if(hash->cant == 0) return NULL;
    if(hash_pertenece(hash, clave)){
        size_t i = codigo_hash(clave, hash->tam);
        while(i != hash->tam){
            if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
                void* devolver = hash->tabla[i].dato;
                free(hash->tabla[i].clave);
                hash->tabla[i].dato = NULL;
                hash->tabla[i].clave = NULL;
                hash->tabla[i].estado = BORRADO;
                hash->cant --;
                return devolver;
            }else if (hash->tabla[i].estado == VACIO){
                return NULL;
            }
            i ++;
        }
        if(i == hash->tam){ 
            i = 0;
            while(i != hash->tam){
                if ((hash->tabla[i].estado == OCUPADO) && (strcmp(hash->tabla[i].clave, clave) == 0)) {
                    void* devolver = hash->tabla[i].dato;
                    free(hash->tabla[i].clave);
                    hash->tabla[i].dato = NULL;
                    hash->tabla[i].clave = NULL;
                    
                    hash->tabla[i].estado = BORRADO;
                    hash->cant --;
                    return devolver;
                }
                i ++;
            }
        }
        return NULL;
    }
    return NULL;
}

struct hash_iter{
    const hash_t* hash;
    size_t actual;
};

hash_iter_t *hash_iter_crear(const hash_t *hash){
    hash_iter_t* iter = malloc(sizeof(hash_iter_t));
    if(!iter) return NULL;
    iter->hash = hash;
    for (size_t i = 0; i < hash->tam; i++){
        if(hash->tabla[i].estado == OCUPADO){
            iter->actual = i;
            break;
        }
    }
    return iter;    
}

bool hash_iter_avanzar(hash_iter_t *iter){
    if(iter->hash->cant == 0) return false;
    if(hash_iter_al_final(iter)) return false;
    iter->actual ++;
    for (size_t i = iter->actual; i < iter->hash->tam; i++){
        if(iter->hash->tabla[i].estado ==OCUPADO){
            iter->actual = i;
            return true;
        }
    }
    return false;
}

const char* hash_iter_ver_actual(const hash_iter_t *iter){
	if (hash_iter_al_final(iter)) return NULL;
	return iter->hash->tabla[iter->actual].clave;
}

bool hash_iter_al_final(const hash_iter_t *iter){
    if (iter->hash->cant == 0) return true;
    if (iter->actual == iter->hash->tam) return true;
    if (iter->hash->tabla[iter->actual].estado ==  VACIO) return true;
    return false;
}

void hash_iter_destruir(hash_iter_t* iter){
    free(iter);
}