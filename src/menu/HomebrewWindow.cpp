/****************************************************************************
 * Copyright (C) 2015 Dimok
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/
#include "HomebrewWindow.h"
extern "C"
{
#include "../patcher/function_hooks.h"
}
#include "common/common.h"
#include "Application.h"
#include "fs/DirList.h"
#include "fs/fs_utils.h"
#include "system/AsyncDeleter.h"
#include "utils/HomebrewXML.h"
#include "HomebrewLaunchWindow.h"
#include "network/FileDownloader.h"
#include <thread>
#include <sstream>


#define DEFAULT_WIILOAD_PORT        4299

#define MAX_BUTTONS_ON_PAGE     4

static HomebrewWindow* thisHomebrewWindow;


std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    log_printf("Here's the formatted string: %s", str.c_str());
    return str;
}

void HomebrewWindow::positionHomebrewButton(homebrewButton* button, int index)
{
    const float cfImageScale = 0.8f;

    button->iconImg = new GuiImage(button->iconImgData);
    button->iconImg->setAlignment(ALIGN_LEFT | ALIGN_MIDDLE);
    button->iconImg->setPosition(60, 0);
    button->iconImg->setScale(cfImageScale);

    button->nameLabel->setAlignment(ALIGN_CENTER | ALIGN_MIDDLE);
    button->nameLabel->setMaxWidth(350, GuiText::SCROLL_HORIZONTAL);
    button->nameLabel->setPosition(0, 70);

    button->coderLabel->setAlignment(ALIGN_LEFT | ALIGN_MIDDLE);
    button->coderLabel->setMaxWidth(170, GuiText::SCROLL_HORIZONTAL);
    button->coderLabel->setPosition(300, 20);

    button->versionLabel->setAlignment(ALIGN_LEFT | ALIGN_MIDDLE);
    button->versionLabel->setMaxWidth(350, GuiText::SCROLL_HORIZONTAL);
    button->versionLabel->setPosition(300, -15);

    button->descriptionLabel->setAlignment(ALIGN_CENTER | ALIGN_MIDDLE);
    button->descriptionLabel->setMaxWidth(350, GuiText::SCROLL_HORIZONTAL);
    button->descriptionLabel->setPosition(0, -60);

    // set the right image for the status
    button->image->setScale(0.9);

    button->button->setImage(button->image);
    button->button->setLabel(button->nameLabel, 0);
    button->button->setLabel(button->descriptionLabel, 1);
    button->button->setLabel(button->coderLabel, 2);
    button->button->setLabel(button->versionLabel, 3);
    button->button->setIcon(button->iconImg);
    button->button->setTrigger(&touchTrigger);
    button->button->setTrigger(&wpadTouchTrigger);
    button->button->setEffectGrow();
//    button->button->setPosition(0, 0);
    //        button->button->setSoundClick(buttonClickSound);
}

int HomebrewWindow::checkIfUpdateOrInstalled(std::string name, std::string version, int totalLocalApps)
{
    for (int x=0; x<totalLocalApps; x++)
    {
        // if shortname matches
        if (!name.compare(homebrewButtons[x].shortname))
        {
            homebrewButtons[x].status = INSTALLED;
            if (version.compare(homebrewButtons[x].version))
            {
                // if version doesn't match
                homebrewButtons[x].status = UPDATE;
            }
//            removeE(homebrewButtons[x].button);

            return x;
        }
    }
    return -1;
}

/**
This method filters the visible apps in in the current tab based on the display mode.

It goes throw the list of all apps (homebrewButtons) and puts only the relevant ones into
the curTabButtons list, which is what's actually rendered.
**/
void HomebrewWindow::filter()
{
    scrollOffY = -120;

    // remove any existing buttons
    for (u32 x=0; x<curTabButtons.size(); x++)
    {
//        log_printf("filter: about to remove button %d", x);
        removeE(curTabButtons[x].button);
    }

    // empty the current tab
    curTabButtons.clear();

    for (u32 x=0; x<homebrewButtons.size(); x++)
    {
        if (homebrewButtons[x].typee == listingMode)
        {
            curTabButtons.push_back(homebrewButtons[x]);
        }
    }

    std::string output = "TOTAL: ";
    for (u32 x=0; x<homebrewButtons.size(); x++)
    {
        output += "["+std::string(homebrewButtons[x].shortname)+"] ";
//        output << homebrewButtons[x].typee;
//        output << "/";
//        output << homebrewButtons[x].status;
//        output << "] ";
    }

    log_printf(output.c_str());

    std::string output2 = "CURRENT: ";
    for (u32 x=0; x<curTabButtons.size(); x++)
    {
        output2 += "["+std::string(curTabButtons[x].shortname)+"] ";
//        output2 << curTabButtons[x].typee;
//        output2 << "/";
//        output2 << curTabButtons[x].status;
//        output2 << "] ";
    }

    log_printf(output2.c_str());

    for (u32 x=0; x<curTabButtons.size(); x++)
    {
//        log_printf("filter: adding button %d, %s", x, curTabButtons[x].shortname.c_str());
        append(curTabButtons[x].button);
//        log_printf("filter: added it");
    }

}

/**
This method fetches the local apps from either /wiiu/games or /wiiu/apps
**/
void HomebrewWindow::loadLocalApps(int mode)
{
    log_printf("loadLocalApps: skipping");
}

/**
This method updates local apps (and fetches server apps if they haven't been fetched yet)
It refreshes the listing on the "home page" of the app store
**/
void HomebrewWindow::refreshHomebrewApps()
{
    log_printf("refreshHomebrewApps: skipping");
}

void HomebrewWindow::findHomebrewIconAndSetImage(std::string shortname, std::string targetIcon)
{
    log_printf("findHomebrewIconAndSetImage: start");
    for (u32 x=0; x<homebrewButtons.size(); x++)
    {
        log_printf("findHomebrewIconAndSetImage: checking element %d", x);
        if (homebrewButtons[x].shortname == shortname)
        {
            if (targetIcon.compare("missing.png") == 0)
                homebrewButtons[x].iconImgData = Resources::GetImageData("missing.png");
            else
                homebrewButtons[x].iconImgData = new GuiImageData((u8*)targetIcon.c_str(), targetIcon.size());
            positionHomebrewButton(&homebrewButtons[x],  x);
            break;
//            removeE(homebrewButtons[x].button);
//            append(homebrewButtons[x].button);
        }
    }
    log_printf("findHomebrewIconAndSetImage: stop");
}

bool HomebrewWindow::checkLocalAppExists(std::string shortname)
{
    for (u32 x=0; x<localAppButtons.size(); x++)
    {
        if (localAppButtons[x].shortname == shortname)
        {
            return true;
        }
    }

    return false;
}

//void HomebrewWindow::fetchThisIcon(int x, std::string targetIconUrl)
//{
//        std::string targetIcon;
//        FileDownloader::getFile(targetIconUrl, targetIcon);
//        cachedIcons.insert(cachedIcons.begin()+targetIcon);
//
//        findHomebrewIconAndSetImage(remoteAppButtons[x].shortname, targetIcon);
//}

void HomebrewWindow::populateIconCache()
{
    log_printf("populateIconCache: skipping");
}

HomebrewWindow::HomebrewWindow(int w, int h)
    : GuiFrame(w, h)
    , hblVersionText("Made By Koopa", 32, glm::vec4(1.0f))
    , installCafText("Launch Cafiine", 40, glm::vec4(1.0f))
    , installCafImgData(Resources::GetImageData("button.png"))
    , installCafImg(installCafImgData)
    , installCafButton(installCafImg.getWidth(), installCafImg.getHeight())
    , touchTrigger(GuiTrigger::CHANNEL_1, GuiTrigger::VPAD_TOUCH)
    , wpadTouchTrigger(GuiTrigger::CHANNEL_2 | GuiTrigger::CHANNEL_3 | GuiTrigger::CHANNEL_4 | GuiTrigger::CHANNEL_5, GuiTrigger::BUTTON_A)
    , buttonLTrigger(GuiTrigger::CHANNEL_ALL, GuiTrigger::BUTTON_L | GuiTrigger::BUTTON_LEFT, true)
    , buttonRTrigger(GuiTrigger::CHANNEL_ALL, GuiTrigger::BUTTON_R | GuiTrigger::BUTTON_RIGHT, true)
{
  //    tcpReceiver.serverReceiveStart.connect(this, &HomebrewWindow::OnTcpReceiveStart);
  //    tcpReceiver.serverReceiveFinished.connect(this, &HomebrewWindow::OnTcpReceiveFinish);

  targetLeftPosition = 0;
  currentLeftPosition = 0;
  listOffset = 0;
  gotDirectorySuccess = false;
  screenLocked = false;
  listingMode = HBL;

  hblVersionText.setAlignment(ALIGN_BOTTOM | ALIGN_RIGHT);
  hblVersionText.setPosition(0, 50.0f);
  append(&hblVersionText);

  //installCafButton.setImage(&installCafImg);
  //installCafButton.setLabel(&installCafText, 0);
  //installCafButton.setEffectGrow();
  //installCafButton.setPosition(0, 40);
  //installCafButton.setAlignment(ALIGN_CENTER | ALIGN_BOTTOM);
  //installCafButton.setTrigger(&touchTrigger);
  //installCafButton.setTrigger(&wpadTouchTrigger);
  //installCafButton.setSoundClick(buttonClickSound);
  //installCafButton.setScale(2.0f);
  //installCafButton.setScaleX(3.0f);

  //append(&installCafButton);
  //installCafButton.clicked.connect(this, &HomebrewWindow::OnInstallCafButtonClick);

  // hblTabBtn.setImage(&hblTabImg);
  // rpxTabBtn.setImage(&rpxTabImg);
  //
  // hblTabBtn.setScale(0.6);
  // rpxTabBtn.setScale(0.6);
  //
  // hblTabBtn.setAlignment(ALIGN_LEFT);
  // rpxTabBtn.setAlignment(ALIGN_LEFT);
  //
  // hblTabBtn.setPosition(0, 85);
  // rpxTabBtn.setPosition(-20, -85);
  //
  // hblTabBtn.setEffectGrow();
  // rpxTabBtn.setEffectGrow();

  //hblTabBtn.setTrigger(&touchTrigger);
  //hblTabBtn.setTrigger(&buttonLTrigger);
  //hblTabBtn.setSoundClick(buttonClickSound);

  //rpxTabBtn.setTrigger(&touchTrigger);
  //rpxTabBtn.setTrigger(&buttonRTrigger);
  //rpxTabBtn.setSoundClick(buttonClickSound);

  //hblTabBtn.clicked.connect(this, &HomebrewWindow::OnHBLTabButtonClick);
  //rpxTabBtn.clicked.connect(this, &HomebrewWindow::OnRPXTabButtonClick);

  //append(&hblTabBtn);
  //append(&rpxTabBtn);

//    refreshHomebrewApps();
}

HomebrewWindow::~HomebrewWindow()
{
  //Resources::RemoveImageData(hblTabImgData);
  //Resources::RemoveImageData(rpxTabImgData);
}

void HomebrewWindow::OnInstallCafButtonClick(GuiButton *button, const GuiController *controller, GuiTrigger *trigger)
{
  log_printf("ARE YOU READY KIDS");
	//PatchMethodHooks();
}

void HomebrewWindow::OnRPXTabButtonClick(GuiButton *button, const GuiController *controller, GuiTrigger *trigger)
{
	if (listingMode == RPX || screenLocked) // already rpx mode
		return;

	listingMode = RPX;
    filter();
    globalUpdatePosition = true;
    log_printf("rpx: Done with moving rpx thing");
}

void HomebrewWindow::OnOpenEffectFinish(GuiElement *element)
{
    //! once the menu is open reset its state and allow it to be "clicked/hold"
    element->effectFinished.disconnect(this);
    element->clearState(GuiElement::STATE_DISABLED);
}

void HomebrewWindow::OnCloseEffectFinish(GuiElement *element)
{
    screenLocked = false;
    //! remove element from draw list and push to delete queue
    removeE(element);
    AsyncDeleter::pushForDelete(element);

    for(u32 i = 0; i < homebrewButtons.size(); i++)
    {
        if (homebrewButtons[i].button != 0)
            homebrewButtons[i].button->clearState(GuiElement::STATE_DISABLED);
    }
}

void HomebrewWindow::OnLaunchBoxCloseClick(GuiElement *element)
{
    element->setState(GuiElement::STATE_DISABLED);
    element->setEffect(EFFECT_FADE, -10, 0);
    element->effectFinished.connect(this, &HomebrewWindow::OnCloseEffectFinish);
}

void HomebrewWindow::OnHomebrewButtonClick(GuiButton *button, const GuiController *controller, GuiTrigger *trigger)
{
    log_printf("clicked a homebrew button");
    if (getHasScrolled() || initialLoadInProgress) {
        return;
    }

    thisHomebrewWindow = this;

    bool disableButtons = false;
//    return;

    for(u32 i = 0; i < homebrewButtons.size(); i++)
    {
        if(button == homebrewButtons[i].button)
        {
            HomebrewLaunchWindow * launchBox = new HomebrewLaunchWindow(homebrewButtons[i], this);
            launchBox->setEffect(EFFECT_FADE, 10, 255);
            launchBox->setState(GuiElement::STATE_DISABLED);
            launchBox->setPosition(0.0f, 30.0f);
            launchBox->effectFinished.connect(this, &HomebrewWindow::OnOpenEffectFinish);
            launchBox->backButtonClicked.connect(this, &HomebrewWindow::OnLaunchBoxCloseClick);
            log_printf("creating launchbox");
            append(launchBox);
            disableButtons = true;
            screenLocked = true;
            break;
        }
    }


    if(disableButtons)
    {
        for(u32 i = 0; i < homebrewButtons.size(); i++)
        {
            if (homebrewButtons[i].button != 0)
                homebrewButtons[i].button->setState(GuiElement::STATE_DISABLED);
        }
    }
}


void HomebrewWindow::draw(CVideo *pVideo)
{
    bool bUpdatePositions = false || globalUpdatePosition;

    if (scrollOffY != lastScrollOffY)
        bUpdatePositions = true;

    if(currentLeftPosition < targetLeftPosition)
    {
        currentLeftPosition += 35;

        if(currentLeftPosition > targetLeftPosition)
            currentLeftPosition = targetLeftPosition;

        bUpdatePositions = true;
    }
    else if(currentLeftPosition > targetLeftPosition)
    {
        currentLeftPosition -= 35;

        if(currentLeftPosition < targetLeftPosition)
            currentLeftPosition = targetLeftPosition;

        bUpdatePositions = true;
    }

    if(bUpdatePositions)
    {

        log_printf("draw: updating positions...");
//        bUpdatePositions = false;
		globalUpdatePosition = false;

        int imageHeight = 210;

        for(u32 i = 0; i < curTabButtons.size(); i++)
        {
//            log_printf("draw: adding a button at pos %d", i);
            float fXOffset = ((i % 2)? 265 : -265);
            float fYOffset = scrollOffY + (imageHeight + 20.0f) * 1.5f - (imageHeight + 15) * ((i%2)? (int)((i-1)/2) : (int)(i/2));
            if (curTabButtons[i].button != 0)
                curTabButtons[i].button->setPosition(currentLeftPosition + fXOffset, fYOffset);
//            log_printf("draw: added that button %d", i);
        }

		// if (listingMode == 1)
		// {
		// 	//hblTabBtn.setPosition(0, 85);
		// 	//rpxTabBtn.setPosition(-20, -85);
		// }
		// else if (listingMode == 2)
		// {
		// 	//hblTabBtn.setPosition(-20, 85);
		// 	rpxTabBtn.setPosition(0, -85);
		// }

        lastScrollOffY = scrollOffY;

        log_printf("draw: done drawing");
    }



    GuiFrame::draw(pVideo);

    if (bUpdatePositions)
        log_printf("draw: done with literally everything now");

}


void refreshHomebrewAppIcons()
{

}

HomebrewWindow* getHomebrewWindow()
{
    return thisHomebrewWindow;
}
