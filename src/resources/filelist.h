/****************************************************************************
 * Loadiine resource files.
 * This file is generated automatically.
 * Includes 26 files.
 *
 * NOTE:
 * Any manual modification of this file will be overwriten by the generation.
 ****************************************************************************/
#ifndef _FILELIST_H_
#define _FILELIST_H_

#include <gctypes.h>

typedef struct _RecourceFile
{
	const char *filename;
	const u8   *DefaultFile;
	const u32  &DefaultFileSize;
	u8		   *CustomFile;
	u32		    CustomFileSize;
} RecourceFile;

extern const u8 bg_png[];
extern const u32 bg_png_size;

extern const u8 button_png[];
extern const u32 button_png_size;

extern const u8 button_click_mp3[];
extern const u32 button_click_mp3_size;

extern const u8 CLOSE_png[];
extern const u32 CLOSE_png_size;

extern const u8 DELETE_BUTTON_png[];
extern const u32 DELETE_BUTTON_png_size;

extern const u8 font_ttf[];
extern const u32 font_ttf_size;

extern const u8 GET_png[];
extern const u32 GET_png_size;

extern const u8 GET_BUTTON_png[];
extern const u32 GET_BUTTON_png_size;

extern const u8 hbl_tab_png[];
extern const u32 hbl_tab_png_size;

extern const u8 INSTALLED_png[];
extern const u32 INSTALLED_png_size;

extern const u8 launchMenuBox_png[];
extern const u32 launchMenuBox_png_size;

extern const u8 LOCAL_png[];
extern const u32 LOCAL_png_size;

extern const u8 missing_png[];
extern const u32 missing_png_size;

extern const u8 missing_square_png[];
extern const u32 missing_square_png_size;

extern const u8 player1_point_png[];
extern const u32 player1_point_png_size;

extern const u8 player2_point_png[];
extern const u32 player2_point_png_size;

extern const u8 player3_point_png[];
extern const u32 player3_point_png_size;

extern const u8 player4_point_png[];
extern const u32 player4_point_png_size;

extern const u8 progressWindow_png[];
extern const u32 progressWindow_png_size;

extern const u8 REINSTALL_BUTTON_png[];
extern const u32 REINSTALL_BUTTON_png_size;

extern const u8 rpx_tab_png[];
extern const u32 rpx_tab_png_size;

extern const u8 screampics_mp3[];
extern const u32 screampics_mp3_size;

extern const u8 splash_png[];
extern const u32 splash_png_size;

extern const u8 titlehbas2_png[];
extern const u32 titlehbas2_png_size;

extern const u8 UPDATE_png[];
extern const u32 UPDATE_png_size;

extern const u8 UPDATE_BUTTON_png[];
extern const u32 UPDATE_BUTTON_png_size;

static RecourceFile RecourceList[] =
{
	{"bg.png", bg_png, bg_png_size, NULL, 0},
	{"button.png", button_png, button_png_size, NULL, 0},
	{"button_click.mp3", button_click_mp3, button_click_mp3_size, NULL, 0},
	{"CLOSE.png", CLOSE_png, CLOSE_png_size, NULL, 0},
	{"DELETE_BUTTON.png", DELETE_BUTTON_png, DELETE_BUTTON_png_size, NULL, 0},
	{"font.ttf", font_ttf, font_ttf_size, NULL, 0},
	{"GET.png", GET_png, GET_png_size, NULL, 0},
	{"GET_BUTTON.png", GET_BUTTON_png, GET_BUTTON_png_size, NULL, 0},
	{"hbl_tab.png", hbl_tab_png, hbl_tab_png_size, NULL, 0},
	{"INSTALLED.png", INSTALLED_png, INSTALLED_png_size, NULL, 0},
	{"launchMenuBox.png", launchMenuBox_png, launchMenuBox_png_size, NULL, 0},
	{"LOCAL.png", LOCAL_png, LOCAL_png_size, NULL, 0},
	{"missing.png", missing_png, missing_png_size, NULL, 0},
	{"missing_square.png", missing_square_png, missing_square_png_size, NULL, 0},
	{"player1_point.png", player1_point_png, player1_point_png_size, NULL, 0},
	{"player2_point.png", player2_point_png, player2_point_png_size, NULL, 0},
	{"player3_point.png", player3_point_png, player3_point_png_size, NULL, 0},
	{"player4_point.png", player4_point_png, player4_point_png_size, NULL, 0},
	{"progressWindow.png", progressWindow_png, progressWindow_png_size, NULL, 0},
	{"REINSTALL_BUTTON.png", REINSTALL_BUTTON_png, REINSTALL_BUTTON_png_size, NULL, 0},
	{"rpx_tab.png", rpx_tab_png, rpx_tab_png_size, NULL, 0},
	{"screampics.mp3", screampics_mp3, screampics_mp3_size, NULL, 0},
	{"splash.png", splash_png, splash_png_size, NULL, 0},
	{"titlehbas2.png", titlehbas2_png, titlehbas2_png_size, NULL, 0},
	{"UPDATE.png", UPDATE_png, UPDATE_png_size, NULL, 0},
	{"UPDATE_BUTTON.png", UPDATE_BUTTON_png, UPDATE_BUTTON_png_size, NULL, 0},
	{NULL, NULL, 0, NULL, 0}
};

#endif
