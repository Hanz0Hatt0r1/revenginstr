'use strict';

// Nevergone Trace Kit v2.1 crash isolation: verified stable v1 hook list by default.
// ABI-dependent values are identified as register words; no arbitrary object memory is dumped.
const PACKAGE = 'com.hippiegame.nevergone';
const TARGET = 'libcocos2dcpp.so';
const LIMITS = { maxHooks: 180, maxEvents: 40000, firstPerSymbol: 40,
                 sampleEvery: 25, maxPerSymbol: 250, flushEveryMs: 750,
                 maxFileEvents: 200, maxPerFileApi: 100, maxStringBytes: 384 };
const CLASS_RULES = [
  ['scene', /GameScene|GameLevels|SceneActions|LoadingLayer|ManagementLayer|AppDelegate/],
  ['player', /MEPlayer|MeActionsSystem|CCJoyStick|ControlsButton|PlayerAction/],
  ['enemy', /EnemyObject|EnemyActions|BattleManager|Attack|GuideManager|LessonOverlay/],
  ['resources', /CCFileUtilsAndroid|SpriteFrameCache|TextureCache|CCSpriteFrame/],
  ['save', /GameSaveData|DataManager/],
  ['lua', /luaL_loadfile|lua_pcall|lua_call|CAddDoString/]
];

// Exact mangled identities verified against the user-provided original ARM32 ELF.
// These are PREFERRED captures and remain independent of automatic class quotas.
const TARGET_HOOKS = {
  '_ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm': 'get_file_data',
  '_ZN7cocos2d6DecodeEPhiS0_j': 'decode',
  '_ZN11EnemyObject12createWithIDEjjjijiN7cocos2d7CCPointEjiib': 'enemy_create',
  '_ZN11EnemyObject10initWithIDEjjjijiN7cocos2d7CCPointEjiib': 'enemy_init',
  '_ZN11EnemyObject19loadEnemyObjectFileEP19GameLevelsEnemyDataffP17ENEMY_ENDLESS_PRO': 'enemy_load',
  '_ZN11EnemyObject17initActionsSystemEPN7cocos2d8CCStringE': 'enemy_actions',
  '_ZN11EnemyObject20initActionsSoundListEPN7cocos2d8CCStringE': 'enemy_sounds',
  '_ZN11EnemyObject6isDeadEv': 'enemy_is_dead',
  '_ZN11EnemyObject16setEnemyHealth_MEi': 'enemy_hp_set',
  '_ZN11EnemyObject16setOlEnemyHealthEii': 'enemy_hp_old',
  '_ZN11EnemyObject9addHealthEf': 'enemy_hp_add',
  '_ZN11EnemyObject16enemyHealthRatioEv': 'enemy_hp_ratio',
  '_ZN11EnemyObject24enemy_sendHarmHealthDataEfi': 'enemy_damage',
  '_ZN11EnemyObject12setEnemyDeadEv': 'enemy_dead',
  '_ZN11EnemyObject17switchBeatenStateE10ENEMYSTATEbf13PLAYERFACEDIR': 'enemy_beaten',
  '_ZN13BattleManager14playerHitEnemyEP11EnemyObjectP8MEPlayerRbS4_': 'battle_hit',
  '_ZN11GameSceneUI10nextLessonE13MEPLAYERSTATE': 'lesson_state',
  '_ZN11GameSceneUI10nextLessonEv': 'lesson_next',
  '_ZN10GameLevels14LoadGameLevelsEPKc': 'level_load',
  '_ZN8MEPlayer10movePlayerEN7cocos2d7CCPointE': 'player_move'
};
// Verified stable selection from the two successful 2026-10-19 v1 runs.
const BASELINE_V1_HOOKS = new Set([
  "JNI_OnLoad",
  "Java_com_hippiegame_nevergone_GooglePlayIABPlugin_nativeOnFailed",
  "Java_com_hippiegame_nevergone_GooglePlayIABPlugin_nativeOnPurchased",
  "Java_com_hippiegame_nevergone_GooglePlayIABPlugin_nativeOnReceiveItemInfo",
  "Java_com_hippiegame_nevergone_GooglePlayIABPlugin_nativeOnRestore",
  "_ZN10GameLevels12LoadGL_SceneEP6HPDataRi",
  "_ZN10GameLevels13LoadGL_GlobalEP6HPDataRi",
  "_ZN10GameLevels14LoadGL_ActionsEP6HPDataRi",
  "_ZN10GameLevels14LoadGameLevelsEPKc",
  "_ZN10GameLevels15LoadGL_PortNodeEP6HPDataRi",
  "_ZN10GameLevels4initEv",
  "_ZN10GameLevels6createEv",
  "_ZN10ShaderGlow19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN10ShaderGlow21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN11AppDelegate29applicationDidEnterBackgroundEv",
  "_ZN11AppDelegate30applicationWillEnterForegroundEv",
  "_ZN11ClothesItem19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN11ClothesItem21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN11DataManager10createDataEj",
  "_ZN11DataManager12createOLDataEji",
  "_ZN11DataManager16loadGameSaveDataEj",
  "_ZN11DataManager18loadOLGameSaveDataEj",
  "_ZN11DataManager18uploadGameSaveDataEv",
  "_ZN11EnemyObject10initWithIDEjjjijiN7cocos2d7CCPointEjiib",
  "_ZN11EnemyObject11initPhysicsEv",
  "_ZN11EnemyObject12createWithIDEjjjijiN7cocos2d7CCPointEjiib",
  "_ZN11EnemyObject12isAttackMissEv",
  "_ZN11EnemyObject14allowHitPlayerEv",
  "_ZN11EnemyObject15initEnemyConfigEv",
  "_ZN11EnemyObject16enemyCenterPointEv",
  "_ZN11EnemyObject17initActionsSystemEPN7cocos2d8CCStringE",
  "_ZN11EnemyObject17switchBeatenStateE10ENEMYSTATEbf13PLAYERFACEDIR",
  "_ZN11EnemyObject19loadEnemyObjectFileEP19GameLevelsEnemyDataffP17ENEMY_ENDLESS_PRO",
  "_ZN11EnemyObject20initActionsSoundListEPN7cocos2d8CCStringE",
  "_ZN11GameSceneUI10nextLessonE13MEPLAYERSTATE",
  "_ZN11GameSceneUI13playVideoDoneEv",
  "_ZN11GameSceneUI14isPlayingVideoEv",
  "_ZN11GameSceneUI15initGameSceneUIEv",
  "_ZN11GameSceneUI16hideLoadingLayerEf",
  "_ZN11GameSceneUI16hideLoadingLayerEv",
  "_ZN11GameSceneUI16showLoadingLayerEfPN7cocos2d8CCObjectEMS1_FvvE",
  "_ZN11GameSceneUI17ShowFinalDamageUIEf",
  "_ZN11GameSceneUI17createShieldLayerEN7cocos2d10_ccColor4BE",
  "_ZN11GameSceneUI17handleStateChangeEb",
  "_ZN11GameSceneUI18UpdataKtplayRedDotEv",
  "_ZN11GameSceneUI18hideOnlinePlayerUIEv",
  "_ZN11GameSceneUI18isShowLoadingLayerEv",
  "_ZN11GameSceneUI18playerInfoCallbackEPN7cocos2d8CCObjectE",
  "_ZN11GameSceneUI18removeLoadingLayerEv",
  "_ZN11GameSceneUI18showOnlinePlayerUIEjjiPKci",
  "_ZN11GameSceneUI20stepHideLoadingLayerEv",
  "_ZN11GameSceneUI21hideControlsAttackKeyEv",
  "_ZN11GameSceneUI21showControlsAttackKeyEv",
  "_ZN11GameSceneUI22showDamageFirstTimeTipEi",
  "_ZN11GameSceneUI24hidePlayerUIAndControlUIEv",
  "_ZN11GameSceneUI24showPlayerUIAndControlUIEv",
  "_ZN11GameSceneUI6createEv",
  "_ZN11StoreSprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN11StoreSprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN12FriendSprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN12FriendSprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN12LoadingLayer17ShowDailyCallbackEf",
  "_ZN12LoadingLayer4initEv",
  "_ZN12LoadingLayer6createEv",
  "_ZN12LoadingLayer6fadeInEv",
  "_ZN12LoadingLayer6onExitEv",
  "_ZN12LoadingLayer7fadeOutEv",
  "_ZN12MEPlayerData23addEndlessOneLifeHealthEt",
  "_ZN12MEPlayerData23addEndlessPhysicalPowerEi",
  "_ZN12MEPlayerData23subEndlessOneLifeHealthEt",
  "_ZN12MEPlayerData4initEv",
  "_ZN12MEPlayerData6createEv",
  "_ZN12StreamSprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameEib",
  "_ZN12StreamSprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameEib",
  "_ZN13ArmbandSprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN13ArmbandSprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN13BattleManager14playerHitEnemyEP11EnemyObjectP8MEPlayerRbS4_",
  "_ZN13BattleManager15AddBeatenEffectEP8MEPlayerP11EnemyObjectN7cocos2d7CCPointEb",
  "_ZN13BattleManager15playerHitPlayerEP8MEPlayerRb",
  "_ZN13GameSceneData4initEv",
  "_ZN13GameSceneData6createEv",
  "_ZN13MEPlayerSound15preloadAllSoundEv",
  "_ZN13MEPlayerSound15stopSoundWithIDEi",
  "_ZN13MEPlayerSound19LoadSoundConfigFileEPKc",
  "_ZN13MEPlayerSound25initMEPlayerSoundWithFileEPKc",
  "_ZN13MEPlayerSound27createMEPlayerSoundWithFileEPKc",
  "_ZN13MEPlayerSound9playSoundEP8MEPlayer",
  "_ZN14ControlsButton10touchBeginEN7cocos2d7CCPointE",
  "_ZN14ControlsButton10touchMovedEN7cocos2d7CCPointE",
  "_ZN14ControlsButton12ccTouchBeganEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN14ControlsButton12ccTouchEndedEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN14ControlsButton12ccTouchMovedEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN14ControlsButton19initWithNormalImageEPKcS1_PN7cocos2d8CCObjectEMS3_FvvE",
  "_ZN14ControlsButton19initWithNormalImageEPKcS1_S1_PN7cocos2d8CCObjectEMS3_FvvE",
  "_ZN14ControlsButton6createEPKcS1_PN7cocos2d8CCObjectEMS3_FvvE",
  "_ZN14ControlsButton6createEPKcS1_S1_PN7cocos2d8CCObjectEMS3_FvvE",
  "_ZN14ControlsButton7onEnterEv",
  "_ZN14ControlsButton8touchEndEN7cocos2d7CCPointE",
  "_ZN14EMReadyUIScene17loadGameSceneDataEP10GameLevels",
  "_ZN14GameLevelsData12initWithDataEPN7cocos2d8CCStringEj",
  "_ZN14GameLevelsData20createGameLevelsDataEPN7cocos2d8CCStringEj",
  "_ZN14GameSceneLayer4initEv",
  "_ZN14HPScale9Sprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN14HPScale9Sprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameENS0_6CCRectE",
  "_ZN14HPScale9Sprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN14HPScale9Sprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameENS0_6CCRectE",
  "_ZN15GameSceneObject10touchEndedEv",
  "_ZN15GameSceneObject12RetouchEndedEv",
  "_ZN15GameSceneObject12initWithDataEP24GameSceneLayerObjectData",
  "_ZN15GameSceneObject12playBoxFloatEPN7cocos2d6CCNodeE",
  "_ZN15GameSceneObject14createWithDataEP24GameSceneLayerObjectData",
  "_ZN15GameSceneObject16playBranchActionEPN7cocos2d6CCNodeE",
  "_ZN15GameSceneObject16playWindowsShineEPSt6vectorIiSaIiEES3_",
  "_ZN15GameSceneObject19playOpenBigTreeAnimEv",
  "_ZN15GameSceneObject20createSceneObjButtonEibiiPKcS1_PN7cocos2d8CCObjectEMS3_FvS4_E",
  "_ZN15GameSceneObject20playCloseBigTreeAnimEv",
  "_ZN15MEPlayerManager10addPlayer2ER9actorDataR15equipWeaponData",
  "_ZN15MEPlayerManager11hidePlayer2Ev",
  "_ZN15MEPlayerManager11showPlayer2Ev",
  "_ZN15MEPlayerManager13removePlayer2Ev",
  "_ZN15MEPlayerManager19initMEPlayerManagerEP9GameScenej",
  "_ZN15MEPlayerManager21sharedMEPlayerManagerEP9GameScenej",
  "_ZN15MEPlayerManager3endEv",
  "_ZN15MEPlayerManager7deallocEv",
  "_ZN15ManagementLayer11restartGameEv",
  "_ZN15ManagementLayer12ccTouchBeganEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN15ManagementLayer12ccTouchEndedEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN15ManagementLayer12ccTouchMovedEPN7cocos2d7CCTouchEPNS0_7CCEventE",
  "_ZN15ManagementLayer13menuDLoadOrUPEPN7cocos2d8CCObjectE",
  "_ZN15ManagementLayer14CreateGemLayerEi",
  "_ZN15ManagementLayer14GoToTapToStartEv",
  "_ZN15ManagementLayer14initBackgroundEv",
  "_ZN15ManagementLayer14initLoginLayerEv",
  "_ZN15ManagementLayer14initSelectHeroEv",
  "_ZN15ManagementLayer14playLoginSoundEv",
  "_ZN15ManagementLayer16createSelectHeroEb",
  "_ZN15ManagementLayer18CreateGaussianBlurEPN7cocos2d6CCNodeEi",
  "_ZN15ManagementLayer18confirmRestartGameEPN7cocos2d8CCObjectE",
  "_ZN15ManagementLayer18initOpeningDalogueEv",
  "_ZN15ManagementLayer19CreateTwoStageFrameEv",
  "_ZN15MeActionsSystem12DamageFactorEv",
  "_ZN15MeActionsSystem12initWithFileEPN7cocos2d8CCStringE13MEPLAYERSTATEfjjjjb",
  "_ZN15MeActionsSystem13startFrameIdxEi",
  "_ZN15MeActionsSystem15creinitWithFileEPN7cocos2d8CCStringE13MEPLAYERSTATEfjjjjb",
  "_ZN15MeActionsSystem16playDoneCallFuncEPN7cocos2d8CCObjectEMS1_FvvE",
  "_ZN15MeActionsSystem4initEv",
  "_ZN15MeActionsSystem4playEfff",
  "_ZN15MeActionsSystem4playEif",
  "_ZN15MeActionsSystem4playEv",
  "_ZN15MeActionsSystem8initNoneEv",
  "_ZN15WareHouseSprite19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN15WareHouseSprite21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN16PlayerActionData4initEv",
  "_ZN16PlayerActionData6createEv",
  "_ZN17ActionDataManager28LoadPlayerActionDataWithFileEiPKc",
  "_ZN17MEPlayerLevelData23LoadPlayerLevelDataFileEPKc",
  "_ZN17MEPlayerLevelData27LoadPlayerLevelDataFile_csvEPKc",
  "_ZN17MEPlayerLevelData4initEv",
  "_ZN17MEPlayerLevelData6createEv",
  "_ZN20ShaderPostProcessing19initWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN20ShaderPostProcessing21createWithSpriteFrameEPN7cocos2d13CCSpriteFrameE",
  "_ZN7cocos2d13CCSpriteFrame15initWithTextureEPNS_11CCTexture2DERKNS_6CCRectE",
  "_ZN7cocos2d13CCSpriteFrame15initWithTextureEPNS_11CCTexture2DERKNS_6CCRectEbRKNS_7CCPointERKNS_6CCSizeE",
  "_ZN7cocos2d13CCSpriteFrame17createWithTextureEPNS_11CCTexture2DERKNS_6CCRectE",
  "_ZN7cocos2d13CCSpriteFrame17createWithTextureEPNS_11CCTexture2DERKNS_6CCRectEbRKNS_7CCPointERKNS_6CCSizeE",
  "_ZN7cocos2d13CCSpriteFrame23initWithTextureFilenameEPKcRKNS_6CCRectE",
  "_ZN7cocos2d13CCSpriteFrame23initWithTextureFilenameEPKcRKNS_6CCRectEbRKNS_7CCPointERKNS_6CCSizeE",
  "_ZN7cocos2d13CCSpriteFrame6createEPKcRKNS_6CCRectE",
  "_ZN7cocos2d13CCSpriteFrame6createEPKcRKNS_6CCRectEbRKNS_7CCPointERKNS_6CCSizeE",
  "_ZN7cocos2d16CCAnimationFrame19initWithSpriteFrameEPNS_13CCSpriteFrameEfPNS_12CCDictionaryE",
  "_ZN8MEPlayer10filpPlayerEb13MEPLAYERSTATE",
  "_ZN8MEPlayer10isComboHitEv",
  "_ZN8MEPlayer10movePlayerEN7cocos2d7CCPointE",
  "_ZN8MEPlayer10resurgenceEv",
  "_ZN8MEPlayer10useSpellIDEj"
]);
const PROFILES = {
  scene: {scene: 60, player: 48, resources: 34, enemy: 24, save: 5, lua: 4, jni: 5},
  combat: {enemy: 95, player: 48, scene: 14, resources: 12, save: 5, lua: 3, jni: 3},
  balanced: {scene: 42, player: 46, enemy: 52, resources: 23, save: 9, lua: 5, jni: 3}
};
let queue = [], fd = -1, api = null, logger = null, attached = false;
let eventCount = 0, bufferDropped = 0, hooks = [], logPath = '', flushing = false;
let pulse = null, activeProfile = 'scene', traceMode = 'stable', fileTrace = 'off', fileEventCount = 0;
let getter = null;
const fileCounts = {};

function shortError(e) { return String(e).slice(0, 200); }
function millis() { return Date.now(); }
function event(o) {
  if (eventCount >= LIMITS.maxEvents) { bufferDropped++; return; }
  eventCount++;
  o.ts_ms = millis();
  queue.push(JSON.stringify(o));
  if (queue.length >= 80) flush();
}
function findExport(lib, name) {
  const m = Process.findModuleByName(lib);
  return m ? m.findExportByName(name) : null;
}
function initNativeIO() {
  if (api) return;
  api = {
    mkdir: new NativeFunction(findExport('libc.so', 'mkdir'), 'int', ['pointer', 'int']),
    open: new NativeFunction(findExport('libc.so', 'open'), 'int', ['pointer', 'int', 'int']),
    write: new NativeFunction(findExport('libc.so', 'write'), 'int', ['int', 'pointer', 'ulong']),
    close: new NativeFunction(findExport('libc.so', 'close'), 'int', ['int']),
    strlen: new NativeFunction(findExport('libc.so', 'strlen'), 'ulong', ['pointer'])
  };
  const fn = findExport('liblog.so', '__android_log_write');
  if (fn) logger = new NativeFunction(fn, 'int', ['int', 'pointer', 'pointer']);
  const dir = '/data/user/0/' + PACKAGE + '/files';
  api.mkdir(Memory.allocUtf8String(dir), 448);
  logPath = dir + '/nevergone-trace-' + Process.id + '.jsonl';
  fd = api.open(Memory.allocUtf8String(logPath), 0x441, 384);
  if (fd < 0) errorLog('trace open failed: ' + logPath);
}
function errorLog(s) {
  try {
    if (logger) logger(6, Memory.allocUtf8String('NGTrace'), Memory.allocUtf8String(s));
    else console.error('[NGTrace]', s);
  } catch (_) { console.error('[NGTrace]', s); }
}
function flush() {
  if (flushing || queue.length === 0) return;
  flushing = true;
  try {
    const lines = queue.splice(0, queue.length).join('\n') + '\n';
    if (fd >= 0) {
      const ptr = Memory.allocUtf8String(lines);
      const length = Number(api.strlen(ptr));
      let sent = 0;
      while (sent < length) {
        const n = api.write(fd, ptr.add(sent), length - sent);
        if (n <= 0) { errorLog('trace write failed'); break; }
        sent += n;
      }
    } else errorLog('trace file unavailable (' + lines.length + ' bytes lost)');
  } catch (e) { errorLog('flush: ' + shortError(e)); }
  finally { flushing = false; }
}
function addrOffset(address, module) {
  try { return address.sub(module.base).toString(); } catch (_) { return '?'; }
}
function category(name) {
  if (name.startsWith('Java_') || name === 'JNI_OnLoad') return 'jni';
  for (const [label, expression] of CLASS_RULES) if (expression.test(name)) return label;
  return null;
}
function importance(name, cat) {
  let n = cat === 'enemy' ? 90 : cat === 'scene' ? 80 : cat === 'player' ? 70 : 40;
  if (/create|init|load|spawn|start|enter|touch|change|damage|hurt|dead|attack|play|updateState|setup/i.test(name)) n += 50;
  if (/get|set|update|tick|draw|visit|render|schedule/i.test(name)) n -= 20;
  if (/^Java_|JNI_OnLoad/.test(name)) n += 100;
  if (/D[012]Ev|C[12]Ev/.test(name)) n -= 30;
  return n;
}
function safeCString(ptr) {
  try {
    if (!ptr || ptr.isNull()) return null;
    // Explicit length may read beyond NUL; native path strings are NUL terminated.
    const value = ptr.readCString();
    return typeof value === 'string' ? value.slice(0, LIMITS.maxStringBytes) : null;
  } catch (_) { return null; }
}
function cleanPath(path) {
  if (!path || /[\x00-\x1f\x7f\ufffd]/.test(path)) return null;
  if (/nevergone-trace-[0-9]+\.jsonl/i.test(path)) return null;
  if (/password|token|secret|cookies|credential|\.key\b/i.test(path)) return null;
  const candidate = path.slice(0, LIMITS.maxStringBytes);
  if (fileTrace !== 'all' && !/(nevergone|\.obb(?:\b|$)|\.plist\b|\.png\b|\.lua\b|\.hpc\b|\.csv\b|\.wbg\b|\.gldata\b|\/assets\/|\/script\/|\/gamedata\/)/i.test(candidate)) return null;
  return candidate;
}
function safeU8(ptr) {
  try { return !ptr || ptr.isNull() ? null : ptr.readU8(); } catch (_) { return null; }
}
function safeU32(ptr) {
  try { return !ptr || ptr.isNull() ? null : ptr.readU32(); } catch (_) { return null; }
}
function safeStack(context, words) {
  const out = [];
  try {
    for (let i = 0; i < words; i++) out.push(context.sp.add(i * 4).readU32());
  } catch (_) { return out; }
  return out;
}
function signed32(word) { return word | 0; }
function getCCString(ptr) {
  if (!getter || !ptr || ptr.isNull()) return null;
  try { return safeCString(getter(ptr)); } catch (_) { return null; }
}
// This is an observation model, not a claim about the complete native C++ object layout.
function inspectEnter(kind, args, context) {
  if (!kind) return null;
  const r = [args[0].toString(), args[1].toString(), args[2].toString(), args[3].toString()];
  const v = {kind, arm_r0_r3: r};
  switch (kind) {
    case 'decode':
      v.source_ptr = r[0];
      v.input_length = signed32(args[1].toUInt32());
      v.destination_ptr = r[2];
      v.key = args[3].toUInt32();
      break;
    case 'get_file_data':
      v.path = cleanPath(safeCString(args[1]));
      v.mode = safeCString(args[2]);
      v.size_out_ptr = r[3];
      break;
    case 'level_load': v.path = cleanPath(safeCString(args[1])); break;
    case 'enemy_create':
      // Static C++ function: first four explicit 32-bit args occupy r0-r3.
      v.first_scalars = [args[0].toUInt32(), args[1].toUInt32(), args[2].toUInt32(), signed32(args[3].toUInt32())];
      v.stack_words_raw = safeStack(context, 8);
      break;
    case 'enemy_init':
      // Member function: r0 is 'this'; next three words are explicit args.
      v.this_ptr = r[0];
      v.first_scalars = [args[1].toUInt32(), args[2].toUInt32(), signed32(args[3].toUInt32())];
      v.stack_words_raw = safeStack(context, 8);
      break;
    case 'enemy_actions': case 'enemy_sounds':
      v.this_ptr = r[0]; v.ccstring_ptr = r[1];
      v.action_name = getCCString(args[1]);
      break;
    case 'enemy_load':
      v.this_ptr = r[0]; v.enemy_data_ptr = r[1];
      v.float_arg_words_raw = [r[2], r[3]];
      v.remaining_ptr_raw = safeStack(context, 1);
      break;
    case 'enemy_hp_set': v.this_ptr = r[0]; v.health_int = signed32(args[1].toUInt32()); break;
    case 'enemy_hp_old':
      v.this_ptr = r[0]; v.old_health_ints = [signed32(args[1].toUInt32()), signed32(args[2].toUInt32())]; break;
    case 'enemy_hp_add': case 'enemy_damage':
      v.this_ptr = r[0]; v.float_arg_raw = r[1];
      if (kind === 'enemy_damage') v.secondary_int = signed32(args[2].toUInt32());
      break;
    case 'enemy_is_dead': case 'enemy_hp_ratio': case 'enemy_dead':
      v.this_ptr = r[0]; break;
    case 'enemy_beaten':
      v.this_ptr = r[0]; v.state_code = signed32(args[1].toUInt32());
      v.flag = args[2].toUInt32() !== 0; v.float_arg_raw = r[3];
      v.stack_words_raw = safeStack(context, 1);
      break;
    case 'battle_hit':
      v.manager_ptr = r[0]; v.enemy_ptr = r[1]; v.player_ptr = r[2];
      v.bool_ref_1 = r[3]; v.bool_ref_1_before = safeU8(args[3]);
      try { v.bool_ref_2_ptr = context.sp.readPointer().toString();
        v.bool_ref_2_before = safeU8(ptr(v.bool_ref_2_ptr)); } catch (_) { v.bool_ref_2_ptr = null; }
      break;
    case 'lesson_state': v.ui_ptr = r[0]; v.player_state_code = signed32(args[1].toUInt32()); break;
    case 'lesson_next': v.ui_ptr = r[0]; break;
    case 'player_move': v.player_ptr = r[0]; v.point_raw = [r[1], r[2]]; break;
  }
  return v;
}
function inspectLeave(v, retval, args) {
  if (!v) return;
  const k = v.kind;
  if (k === 'decode') {
    const length = v.input_length;
    if (!Number.isInteger(length) || length < 0 || length > 0x1000000) {
      v.sample_mode = 'skipped_length_limit';
      v.sample_count = 0;
      v.formula_matches = null;
    } else if (length === 0) {
      v.sample_mode = 'empty';
      v.sample_count = 0;
      v.formula_matches = null;
    } else {
      const planned = Math.min(length, 128);
      let checked = 0, matches = true;
      try {
        const source = ptr(v.source_ptr), destination = ptr(v.destination_ptr);
        for (let sample = 0; sample < planned; sample++) {
          const index = planned === 1 ? 0 : Math.floor(sample * (length - 1) / (planned - 1));
          const input = source.add(index).readU8();
          const output = destination.add(index).readU8();
          const expected = ((input ^ v.key) - (index % 127)) & 0xff;
          checked++;
          if (output !== expected) matches = false;
        }
        v.formula_matches = matches;
      } catch (e) {
        v.formula_matches = null;
        v.sample_error = shortError(e);
      }
      v.sample_count = checked;
      v.sample_mode = length <= 128 ? 'full' : 'evenly_spaced';
    }
  } else if (k === 'get_file_data') {
    v.returned_data_pointer = retval.toString();
    v.success = !retval.isNull();
    try { v.file_size = safeU32(ptr(v.size_out_ptr)); } catch (_) { v.file_size = null; }
  } else if (k === 'enemy_is_dead') {
    v.returned_bool = (retval.toUInt32() & 0xff) !== 0;
  } else if (k === 'battle_hit') {
    v.bool_ref_1_after = safeU8(ptr(v.bool_ref_1));
    if (v.bool_ref_2_ptr) v.bool_ref_2_after = safeU8(ptr(v.bool_ref_2_ptr));
  }
}
function traceFn(module, symbol, cls) {
  const name = symbol.name;
  const offset = addrOffset(symbol.address, module);
  const kind = TARGET_HOOKS[name] || null;
  let observed = 0;
  try {
    const listener = Interceptor.attach(symbol.address, {
      onEnter(args) {
        observed++;
        const retain = observed <= LIMITS.firstPerSymbol ||
          (observed <= LIMITS.maxPerSymbol && observed % LIMITS.sampleEvery === 0);
        this.traceRetain = retain;
        if (!retain || eventCount >= LIMITS.maxEvents) return;
        this.startMs = millis();
        this.captureArgs = [args[0].toString(), args[1].toString(), args[2].toString()];
        this.callsite = addrOffset(this.returnAddress, module);
        this.tid = Process.getCurrentThreadId();
        try { this.typed = inspectEnter(kind, args, this.context); }
        catch (e) { this.typed = {kind, decode_error: shortError(e)}; }
      },
      onLeave(retval) {
        if (!this.traceRetain || eventCount >= LIMITS.maxEvents) return;
        try { inspectLeave(this.typed, retval); }
        catch (e) { if (this.typed) this.typed.leave_error = shortError(e); }
        const data = {type: 'call', cls, symbol: name, offset,
          tid: this.tid, callsite: this.callsite,
          args_raw: this.captureArgs, ret_raw: retval.toString(),
          duration_ms: millis() - this.startMs, ordinal: observed};
        if (this.typed) data.typed = this.typed;
        event(data);
      }
    });
    hooks.push(listener);
    event({type: 'hook', cls, symbol: name, offset, kind, size: symbol.size || null});
    return true;
  } catch (e) {
    event({type: 'hook_error', symbol: name, offset, error: shortError(e)});
    return false;
  }
}
function attachLibrary() {
  if (attached) return;
  const module = Process.findModuleByName(TARGET);
  if (!module) return;
  attached = true;
  try {
    const collected = [], present = {};
    let all = 0, skippedTiny = 0;
    for (const s of module.enumerateSymbols()) {
      all++;
      if (s.type !== 'function' || !s.address || !s.name) continue;
      if (typeof s.size === 'number' && s.size < 4) { skippedTiny++; continue; }
      if (s.name === '_ZNK7cocos2d8CCString10getCStringEv') {
        try { getter = new NativeFunction(s.address, 'pointer', ['pointer']); }
        catch (e) { event({type: 'accessor_error', symbol: s.name, error: shortError(e)}); }
      }
      const cls = category(s.name);
      if (cls) collected.push({symbol: s, cls, priority: importance(s.name, cls)});
      if (TARGET_HOOKS[s.name]) present[s.name] = s;
    }
    collected.sort((a,b) => b.priority - a.priority || a.symbol.name.localeCompare(b.symbol.name));
    const seen = new Set(), quotas = PROFILES[activeProfile] || PROFILES.scene, perClass = {};
    const selected = [];
    function add(s, cls) {
      if (!s || seen.has(s.address.toString()) || selected.length >= LIMITS.maxHooks) return;
      seen.add(s.address.toString()); selected.push({symbol:s,cls});
      perClass[cls] = (perClass[cls] || 0) + 1;
    }
    if (traceMode === 'stable') {
      // V1's observed working selection; no new functions and no libc-wide tracing.
      for (const x of collected) if (BASELINE_V1_HOOKS.has(x.symbol.name)) add(x.symbol, x.cls);
    } else if (traceMode === 'resources') {
      // A narrow, independent experiment. Never combine libc-wide hooks with the
      // full engine hook set while diagnosing the Tap to Start crash.
      const names = new Set([
        '_ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm',
        '_ZN7cocos2d6DecodeEPhiS0_j',
        '_ZN10GameLevels14LoadGameLevelsEPKc'
      ]);
      for (const x of collected) if (names.has(x.symbol.name)) add(x.symbol, x.cls);
      add(present['_ZN7cocos2d6DecodeEPhiS0_j'], 'resources');
    } else {
      // Research-only / explicitly opt-in; not accepted as stable on Android.
      for (const name of Object.keys(TARGET_HOOKS)) add(present[name], category(name) || 'enemy');
      for (const x of collected) if (x.symbol.name.indexOf('GuideManager') === -1 &&
          (perClass[x.cls] || 0) < (quotas[x.cls] || 0)) add(x.symbol, x.cls);
      for (const x of collected) if (x.symbol.name.indexOf('GuideManager') === -1) add(x.symbol, x.cls);
    }
    let installed = 0;
    for (const x of selected) if (traceFn(module, x.symbol, x.cls)) installed++;
    event({type: 'module', name: TARGET, base: module.base.toString(), size: module.size,
      enumerated_symbols: all, matching_functions: collected.length,
      selected_hooks: selected.length, installed_hooks: installed,
      skipped_tiny_symbols: skippedTiny,
      priority_hooks_found: Object.keys(present).length,
      priority_hooks_requested: Object.keys(TARGET_HOOKS).length,
      max_hooks: LIMITS.maxHooks, profile: activeProfile, trace_mode: traceMode});
    flush();
  } catch (e) { event({type:'attach_error', error:shortError(e)}); flush(); }
}
function attachLoaders() {
  for (const lib of ['dlopen','android_dlopen_ext']) {
    const addr = findExport('libdl.so',lib) || findExport('libc.so',lib);
    if (!addr) continue;
    try {
      hooks.push(Interceptor.attach(addr, {
        onEnter(args) {
          const path = safeCString(args[0]) || '';
          this.need = path.includes(TARGET);
        },
        onLeave() { if (this.need) { event({type:'loader',name:TARGET}); setImmediate(attachLibrary); } }
      }));
    } catch (e) { event({type:'loader_hook_error',fn:lib,error:shortError(e)}); }
  }
}
function attachFileIO() {
  if (fileTrace === 'off' || traceMode === 'stable') return;
  const names = [['open',0],['open64',0],['openat',1],['openat64',1],['fopen',0],['fopen64',0]];
  const seen = new Set();
  for (const [name,index] of names) {
    const addr = findExport('libc.so',name);
    if (!addr || seen.has(addr.toString())) continue;
    seen.add(addr.toString());
    try {
      hooks.push(Interceptor.attach(addr, {
        onEnter(args) {
          this.path = null;
          if (fileEventCount >= LIMITS.maxFileEvents || (fileCounts[name]||0) >= LIMITS.maxPerFileApi) return;
          const path = cleanPath(safeCString(args[index]));
          if (!path) return;
          this.path = path;
          this.fdarg = index === 1 ? args[0].toInt32() : null;
          this.flags = (name.startsWith('fopen')) ? safeCString(args[1]) : args[index+1].toString();
        },
        onLeave(retval) {
          if (!this.path || fileEventCount >= LIMITS.maxFileEvents) return;
          fileCounts[name] = (fileCounts[name]||0) + 1; fileEventCount++;
          const success = name.startsWith('fopen') ? !retval.isNull() : retval.toInt32() >= 0;
          event({type:'file_access', api:name, path:this.path,
            dirfd:this.fdarg, flags:this.flags, success, result_raw:retval.toString(),
            tid:Process.getCurrentThreadId()});
        }
      }));
      event({type:'file_hook',api:name});
    } catch (e) { event({type:'file_hook_error',api:name,error:shortError(e)}); }
  }
}
function start(stage, parameters) {
  try {
    activeProfile = (parameters && PROFILES[parameters.profile]) ? parameters.profile : 'scene';
    traceMode = (parameters && ['stable','resources','extended'].includes(parameters.trace_mode)) ? parameters.trace_mode : 'stable';
    fileTrace = (parameters && ['off','game','all'].includes(parameters.file_trace)) ? parameters.file_trace : 'off';
    initNativeIO();
    event({type:'header',format:'nevergone-trace/2',stage,pid:Process.id,
      arch:Process.arch,package:PACKAGE,source:'Frida Gadget script',
      limits:LIMITS,trace_mode:traceMode,parameters:parameters||{},disclaimer:'ARM32 register observations; selected typed ABI fields; no arbitrary object dump'});
    attachLoaders();
    attachLibrary();
    attachFileIO();
    if (traceMode === 'stable' && fileTrace !== 'off') event({type:'notice',message:'stable mode ignores file_trace to preserve v1 hook behavior'});
    pulse = setInterval(() => { attachLibrary(); flush(); }, LIMITS.flushEveryMs);
    flush();
    errorLog('trace v2.1 mode=' + traceMode + ' running: ' + logPath);
  } catch (e) { errorLog('init failed: ' + shortError(e)); }
}
rpc.exports = {
  init(stage, parameters) { start(stage, parameters); },
  dispose() {
    if (pulse !== null) { clearInterval(pulse); pulse = null; }
    event({type:'footer',event_count:eventCount,dropped:bufferDropped,file_events:fileEventCount});
    flush();
    if (fd >= 0 && api) { api.close(fd); fd = -1; }
  }
};
