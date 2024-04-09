#define LUA_LIB

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "protocol.h"

int lparse(lua_State* L) {
  int ret = 0;
  struct sge_proto* proto = NULL;
  const char *text = NULL, *err = NULL;
  size_t len = 0;

  text = luaL_checklstring(L, 1, &len);
  if (l_unlikely(!text)) {
    return luaL_argerror(L, 1, NULL);
  }

  proto = sge_parse(text, len);
  if (NULL == proto) {
    lua_pushstring(L, "memory not enough.");
    return lua_error(L);
  }

  ret = sge_protocol_error(proto, &err);
  if (SGE_OK != ret) {
    lua_pushstring(L, err);
    sge_print_protocol(proto);
    return lua_error(L);
  }

  lua_pushlightuserdata(L, proto);

  return 1;
}

int lparse_file(lua_State* L) {
  int ret = 0;
  const char* filename = NULL;
  const char* err = NULL;
  struct sge_proto* proto = NULL;

  filename = luaL_checkstring(L, 1);
  if (l_unlikely(!filename)) {
    return luaL_argerror(L, 1, NULL);
  }

  proto = sge_parse_file(filename);
  if (NULL == proto) {
    lua_pushstring(L, "memory not enough.");
    return lua_error(L);
  }

  ret = sge_protocol_error(proto, &err);
  if (SGE_OK != ret) {
    lua_pushstring(L, err);
    sge_print_protocol(proto);
    return lua_error(L);
  }

  lua_pushlightuserdata(L, proto);

  return 1;
}

int ldebug(lua_State* L) {
  struct sge_proto* proto = NULL;

  proto = (struct sge_proto*)lua_touserdata(L, 1);
  if (l_unlikely(!proto)) {
    return luaL_argerror(L, 1, "proto expected");
  }

  sge_print_protocol(proto);

  return 1;
}

LUAMOD_API int luaopen_libsgeproto_core(lua_State* L) {
  luaL_checkversion(L);

  luaL_Reg l[] = {{"parse", lparse}, {"parse_file", lparse_file}, {"debug", ldebug}, {NULL, NULL}};
  luaL_newlib(L, l);

  return 1;
}
