```
undefined8 FUN_004018c5(int argc,undefined8 *argv)

{
  undefined uVar1;
  int compare;
  undefined8 uVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  long in_FS_OFFSET;
  ulong local_c8;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined local_a8;
  undefined local_98 [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_b8 = 0x645f736b316c4c7a;
  local_b0 = 0x495f6730545f6d34;
  local_a8 = 0;
  FUN_004017b5(
              "/===========================================================================\\\n|                Welcome to BIC Winter CTF \\0/                               |\n+========== =================================================================+\n"
              );
  if (argc == 3) {
    FUN_004017b5(" ~> Verifying.");
    FUN_00401805(3);
    compare = FUN_00401130(argv[1],"hacker");
    if (compare == 0) {
      lVar3 = FUN_00401180(argv[2]);
      lVar3 = FUN_0041ff20(lVar3 + 1);
      FUN_00401020(lVar3,argv[2]);
      local_c8 = 0;
      while( true ) {
        uVar5 = FUN_00401180(lVar3);
        if (uVar5 >> 1 <= local_c8) break;
        uVar1 = *(undefined *)(local_c8 + lVar3);
        lVar4 = FUN_00401180(lVar3);
        *(undefined *)(local_c8 + lVar3) = *(undefined *)(lVar3 + (lVar4 - local_c8) + -1);
        lVar4 = FUN_00401180(lVar3);
        *(undefined *)((lVar4 - local_c8) + -1 + lVar3) = uVar1;
        local_c8 = local_c8 + 1;
      }
      FUN_00401805(3);
      compare = FUN_004010d0(lVar3,&local_b8,0x11);
      if (compare == 0) {
        FUN_004017b5("Correct!\n");
        FUN_004017b5("Welcome back!\n");
        FUN_0040ba90(local_98,0x80,)
        FUN_004017b5(local_98);
      }
      else {
        FUN_004017b5("ACCESS DENIED\n");
        FUN_004017b5(" ~> Incorrect password\n");
      }
      uVar2 = 0;
    }
    else {
      FUN_004127f0(10);
      FUN_004017b5("ACCESS DENIED\n");
      FUN_004017b5(" ~> Incorrect username\n");
      uVar2 = 1;
    }
  }
  else {
    FUN_00412650("[ERROR] Login information missing");
    FUN_0040b9c0("Usage: %s <username> <password>\n",*argv);
    uVar2 = 1;
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    FUN_00452730();
  }
  return uVar2;
}
